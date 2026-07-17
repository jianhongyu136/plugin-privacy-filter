package main

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// streamCarryMaxEntries bounds the number of per-stream states. End markers
	// normally release active state; the hard cap still bounds memory if markers
	// are missed or concurrency is excessive.
	streamCarryMaxEntries = 4096
	// streamCarryMaxBytes bounds withheld bytes per stream. A larger incomplete
	// SSE line is emitted unchanged rather than retained and repeatedly copied.
	streamCarryMaxBytes = 1 << 20
	// streamStoreMaxBytes bounds aggregate retained carry and allowlist data.
	// LRU eviction keeps the process-wide state bounded even if many streams
	// concurrently stop on incomplete SSE lines.
	streamStoreMaxBytes = 32 << 20
	// streamAllowlistMaxTokens bounds the request tokens and labels retained per
	// stream. Requests beyond this limit remain safe: excess placeholders are
	// left unrestored rather than growing persistent state or per-chunk work.
	streamAllowlistMaxTokens = 1024
	// streamCarryTTL bounds how long inactive legacy state may live before it is
	// considered abandoned and eligible for eviction. Stateful streams remain
	// active until their end marker unless a hard memory cap is reached.
	streamCarryTTL = 5 * time.Minute
)

// streamEntry holds the state carried across chunks of one stream: the
// request-scoped token allowlist (computed once, reused for every chunk) and
// any bytes withheld because they may be the start of a token split across the
// next chunk boundary. touchedAt drives TTL and LRU-style eviction.
type streamEntry struct {
	key       string
	allowed   map[string]struct{}
	hasAllow  bool
	active    bool
	carry     []byte
	content   map[string]string
	touchedAt time.Time
	element   *list.Element
	bytes     int
}

// streamStore is a bounded map of per-stream state. Active state is retained
// until an end marker, while inactive legacy state is TTL-evicted. Hard entry
// and byte caps keep memory bounded if lifecycle markers are missed.
type streamStore struct {
	mu             sync.Mutex
	entries        map[string]*streamEntry
	lru            *list.List
	totalBytes     int
	maxBytes       int
	ttl            time.Duration
	cleanupRunning bool
	cleanupStop    chan struct{}
	cleanupDone    chan struct{}
}

func newStreamStore() *streamStore {
	return newStreamStoreWithLimits(streamCarryTTL, streamStoreMaxBytes)

}

func newStreamStoreWithLimits(ttl time.Duration, maxBytes int) *streamStore {
	return &streamStore{
		entries:  make(map[string]*streamEntry),
		lru:      list.New(),
		ttl:      ttl,
		maxBytes: maxBytes,
	}
}

// allowlist returns the cached per-request token allowlist for key, computing
// it once via build on first use. Caching avoids re-scanning the full request
// body with a regex on every chunk of a stream, which was O(chunks x bodySize).
func (s *streamStore) allowlist(key string, build func() map[string]struct{}) map[string]struct{} {
	s.mu.Lock()
	now := time.Now()
	s.purgeLocked(now)
	active := false
	if e, ok := s.entries[key]; ok {
		active = e.active
		if e.hasAllow {
			s.touchLocked(e, now)
			allowed := e.allowed
			s.mu.Unlock()
			return allowed
		}
	}
	s.mu.Unlock()

	allowed := build()
	s.mu.Lock()
	defer s.mu.Unlock()
	now = time.Now()
	s.purgeLocked(now)
	e := s.getOrCreateLocked(key, now)
	// Stateful lifecycle calls are serialized per StreamID. Preserve the active
	// marker if hard-cap pressure evicted the entry during the unlocked scan.
	e.active = e.active || active
	if !e.hasAllow {
		e.allowed = allowed
		e.hasAllow = true
		s.resizeEntryLocked(e)
		if e.bytes > s.maxBytes {
			s.removeLocked(e)
			return allowed
		}
		s.evictBytesLocked(e)
	}
	s.touchLocked(e, now)
	return e.allowed
}

// takeCarry returns and clears any withheld bytes for key, mirroring the
// previous load-then-delete consume pattern (but keeping the cached allowlist).
func (s *streamStore) takeCarry(key string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok {
		return nil
	}
	c := e.carry
	e.carry = nil
	s.resizeEntryLocked(e)
	s.touchLocked(e, time.Now())
	return c
}

// setCarry records withheld bytes for key, purging expired entries and
// enforcing the size cap (evicting the least-recently-touched) first.
func (s *streamStore) setCarry(key string, data []byte) bool {
	if len(data) > streamCarryMaxBytes {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.purgeLocked(now)
	e := s.getOrCreateLocked(key, now)
	e.carry = append([]byte(nil), data...)
	s.resizeEntryLocked(e)
	if e.bytes > s.maxBytes {
		s.removeLocked(e)
		return false
	}
	s.evictBytesLocked(e)
	s.touchLocked(e, now)
	return true
}

// reset drops all state for key (used on the stream-init call).
func (s *streamStore) reset(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[key]; ok {
		s.removeLocked(e)
	}
}

// begin replaces any stale state for key and marks the stream active so normal
// idle cleanup and capacity pressure prefer abandoned or completed entries.
func (s *streamStore) begin(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if e, ok := s.entries[key]; ok {
		s.removeLocked(e)
	}
	e := s.getOrCreateLocked(key, now)
	e.active = true
	s.resizeEntryLocked(e)
	s.touchLocked(e, now)
}

// end releases all state retained for a completed stream.
func (s *streamStore) end(key string) {
	s.reset(key)
}

func (s *streamStore) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[string]*streamEntry)
	s.lru.Init()
	s.totalBytes = 0
}

func (s *streamStore) startCleanup() {
	s.mu.Lock()
	if s.cleanupRunning {
		s.mu.Unlock()
		return
	}
	s.cleanupRunning = true
	s.cleanupStop = make(chan struct{})
	s.cleanupDone = make(chan struct{})
	stop, done, ttl := s.cleanupStop, s.cleanupDone, s.ttl
	s.mu.Unlock()
	go s.cleanupLoop(stop, done, ttl)
}

func (s *streamStore) stopCleanup() {
	s.mu.Lock()
	if !s.cleanupRunning {
		s.mu.Unlock()
		return
	}
	stop, done := s.cleanupStop, s.cleanupDone
	s.cleanupRunning = false
	s.cleanupStop = nil
	s.cleanupDone = nil
	close(stop)
	s.mu.Unlock()
	<-done
}

func (s *streamStore) cleanupLoop(stop <-chan struct{}, done chan<- struct{}, ttl time.Duration) {
	defer close(done)
	interval := ttl
	if interval > time.Second {
		interval = time.Second
	}
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			s.purgeLocked(time.Now())
			s.mu.Unlock()
		case <-stop:
			return
		}
	}
}

// has reports whether any state exists for key without consuming it.
func (s *streamStore) has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(time.Now())
	_, ok := s.entries[key]
	return ok
}

// getOrCreateLocked returns the entry for key, creating it (after enforcing the
// size cap) if absent. The caller must hold s.mu.
func (s *streamStore) getOrCreateLocked(key string, now time.Time) *streamEntry {
	if e, ok := s.entries[key]; ok {
		return e
	}
	s.evictLocked(streamCarryMaxEntries - 1)
	e := &streamEntry{key: key, touchedAt: now}
	e.element = s.lru.PushFront(e)
	s.entries[key] = e
	return e
}

// purgeLocked removes entries whose last touch is older than the TTL. The
// caller must hold s.mu.
func (s *streamStore) purgeLocked(now time.Time) {
	for element := s.lru.Back(); element != nil; {
		e := element.Value.(*streamEntry)
		previous := element.Prev()
		if e.active {
			element = previous
			continue
		}
		if now.Sub(e.touchedAt) <= s.ttl {
			return
		}
		s.removeLocked(e)
		element = previous
	}
}

// evictLocked removes least-recently-touched entries until at most max remain.
// The caller must hold s.mu.
func (s *streamStore) evictLocked(max int) {
	for len(s.entries) > max {
		candidate := s.evictionCandidateLocked(nil)
		if candidate == nil {
			return
		}
		s.removeLocked(candidate)
	}
}

func (s *streamStore) touchLocked(e *streamEntry, now time.Time) {
	e.touchedAt = now
	s.lru.MoveToFront(e.element)
}

func (s *streamStore) resizeEntryLocked(e *streamEntry) {
	s.totalBytes -= e.bytes
	e.bytes = len(e.key) + len(e.carry)
	for token := range e.allowed {
		e.bytes += len(token)
	}
	for channel, pending := range e.content {
		e.bytes += len(channel) + len(pending)
	}
	s.totalBytes += e.bytes
}

func (s *streamStore) evictBytesLocked(keep *streamEntry) {
	for s.totalBytes > s.maxBytes && s.lru.Len() > 1 {
		candidate := s.evictionCandidateLocked(keep)
		if candidate == nil {
			return
		}
		s.removeLocked(candidate)
	}
}

func (s *streamStore) evictionCandidateLocked(keep *streamEntry) *streamEntry {
	for element := s.lru.Back(); element != nil; element = element.Prev() {
		candidate := element.Value.(*streamEntry)
		if candidate != keep && !candidate.active {
			return candidate
		}
	}
	for element := s.lru.Back(); element != nil; element = element.Prev() {
		candidate := element.Value.(*streamEntry)
		if candidate != keep {
			return candidate
		}
	}
	return nil
}

func (s *streamStore) removeLocked(e *streamEntry) {
	if e == nil {
		return
	}
	delete(s.entries, e.key)
	s.lru.Remove(e.element)
	s.totalBytes -= e.bytes
}

// streamCarry holds per-stream state. New hosts key it by a unique StreamID;
// legacy hosts fall back to streamKey(requestBody).
//
// Legacy limitation: two concurrent streams with identical request bodies
// share a key. The request-scoped allowlist keeps this same-origin: both streams
// may only restore tokens their shared request actually emitted.
var streamCarry = newStreamStore()

func init() {
	streamCarry.startCleanup()
}

// collectTokens returns the set of complete tokens present in data. It is used
// to build a per-request allowlist from the redacted request body so response
// and stream restoration only reinstates secrets this request actually emitted,
// never tokens minted for a different request that happen to share the vault.
func collectTokens(data []byte, tokenRe *regexp.Regexp, v *vault) map[string]struct{} {
	set := make(map[string]struct{})
	if tokenRe == nil || v == nil {
		return set
	}
	for offset := 0; offset < len(data) && len(set) < streamAllowlistMaxTokens; {
		match := tokenRe.FindIndex(data[offset:])
		if match == nil {
			break
		}
		start, end := offset+match[0], offset+match[1]
		token := string(data[start:end])
		if _, seen := set[token]; !seen {
			if _, ok := v.Get(token); ok {
				set[token] = struct{}{}
			}
		}
		offset = end
	}
	// Another request interceptor may JSON-reencode the already-redacted body,
	// escaping token angle brackets as \u003c/\u003e. Decode valid JSON once and
	// search string values semantically so those exact mapped tokens remain in
	// the request-scoped allowlist.
	if len(set) < streamAllowlistMaxTokens && bytes.Contains(data, []byte(`\u00`)) {
		var doc any
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&doc); err == nil {
			var trailing any
			if err := dec.Decode(&trailing); err == io.EOF {
				collectTokensFromJSON(doc, tokenRe, v, set)
			}
		}
	}
	return set
}

func collectTokensFromJSON(node any, tokenRe *regexp.Regexp, v *vault, set map[string]struct{}) {
	if len(set) >= streamAllowlistMaxTokens {
		return
	}
	switch value := node.(type) {
	case string:
		for offset := 0; offset < len(value) && len(set) < streamAllowlistMaxTokens; {
			match := tokenRe.FindStringIndex(value[offset:])
			if match == nil {
				return
			}
			start, end := offset+match[0], offset+match[1]
			token := value[start:end]
			if _, ok := v.Get(token); ok {
				set[token] = struct{}{}
			}
			offset = end
		}
	case []any:
		for _, child := range value {
			collectTokensFromJSON(child, tokenRe, v, set)
		}
	case map[string]any:
		for _, child := range value {
			collectTokensFromJSON(child, tokenRe, v, set)
		}
	}
}

func tokenLabels(tokens map[string]struct{}) []string {
	labels := make(map[string]struct{})
	for token := range tokens {
		underscore := len(token) - tokenHexLen - 2
		if underscore <= 1 || token[0] != '<' || token[len(token)-1] != '>' || token[underscore] != '_' {
			continue
		}
		labels[token[1:underscore]] = struct{}{}
	}
	out := make([]string, 0, len(labels))
	for label := range labels {
		out = append(out, label)
	}
	return out
}

// restoreBody replaces complete <LABEL_hash> tokens with their original values
// from the shared vault. When allowed is non-nil only tokens in that set are
// restored (request-scoped); a nil set restores any known token (unrestricted).
// Tokens with no vault mapping, or not in the allowlist, are left verbatim
// (fail-open: shows the placeholder, never a wrong secret).
//
// Restoration is structure-aware to avoid corrupting the payload when an
// original secret contains characters that require escaping (quote, backslash,
// newline): JSON documents and SSE "data:" JSON frames are decoded, the secret
// is reinstated inside the decoded string, and the payload is re-encoded so
// escaping stays valid. Plain text falls back to byte-level replacement.
//
// The vault is supplied by the caller (read from a single runtime snapshot)
// rather than fetched here, so the label used to build tokenRe/allowed and the
// vault used to resolve them always come from the same reconfigure generation.
func restoreBody(data []byte, tokenRe *regexp.Regexp, allowed map[string]struct{}, v *vault) []byte {
	return restoreBodyForMediaType(data, tokenRe, allowed, v, "")
}

func restoreBodyForMediaType(data []byte, tokenRe *regexp.Regexp, allowed map[string]struct{}, v *vault, mediaType string) []byte {
	if v == nil || len(data) == 0 {
		return data
	}
	// A non-nil but empty allowlist means the originating request emitted no
	// tokens, so nothing in the response can be ours to restore.
	if allowed != nil && len(allowed) == 0 {
		return data
	}
	if isJSONMediaType(mediaType) {
		if restored, ok := restoreJSONDoc(data, tokenRe, allowed, v); ok {
			return restored
		}
		return data
	}
	if strings.EqualFold(mediaType, "text/event-stream") {
		return restoreSSE(data, tokenRe, allowed, v)
	}
	if mediaType != "" {
		if tokenRe.Find(data) == nil {
			return data
		}
		return restoreRaw(data, tokenRe, allowed, v)
	}
	// Try structure-aware restoration first so tokens are recognized regardless
	// of how the upstream encoder rendered them: a token may appear literally as
	// <LABEL_hash> or JSON-escaped as \u003cLABEL_hash\u003e. Decoding the JSON
	// normalizes both. restoreJSONDoc only rewrites the body when it actually
	// restores something, so token-free responses are left byte-for-byte intact.
	if restored, ok := restoreJSONDoc(data, tokenRe, allowed, v); ok {
		return restored
	}
	if isSSEData(data) {
		return restoreSSE(data, tokenRe, allowed, v)
	}
	if looksLikeJSON(data) {
		// Never inject raw plaintext into malformed JSON-looking content. Doing
		// so can corrupt syntax and can turn an upstream parse error into a
		// response that exposes a secret.
		return data
	}
	if tokenRe.Find(data) == nil {
		return data
	}
	return restoreRaw(data, tokenRe, allowed, v)
}

func isJSONMediaType(mediaType string) bool {
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

// restorer reinstates allowed tokens inside decoded JSON string leaves and
// records whether any substitution actually happened.
type restorer struct {
	tokenRe *regexp.Regexp
	allowed map[string]struct{}
	v       *vault
	changed bool
}

// restoreString reinstates allowed tokens inside a single decoded string.
func (r *restorer) restoreString(s string) string {
	return r.tokenRe.ReplaceAllStringFunc(s, func(match string) string {
		if r.allowed != nil {
			if _, ok := r.allowed[match]; !ok {
				return match
			}
		}
		if original, ok := r.v.Get(match); ok {
			r.changed = true
			return original
		}
		return match
	})
}

// walk recurses a decoded JSON value, restoring tokens in string leaves.
func (r *restorer) walk(node any) any {
	switch n := node.(type) {
	case map[string]any:
		for k, child := range n {
			n[k] = r.walk(child)
		}
		return n
	case []any:
		for i, child := range n {
			n[i] = r.walk(child)
		}
		return n
	case string:
		return r.restoreString(n)
	default:
		return node
	}
}

// restoreRaw performs byte-level token replacement for non-JSON payloads.
func restoreRaw(data []byte, tokenRe *regexp.Regexp, allowed map[string]struct{}, v *vault) []byte {
	return tokenRe.ReplaceAllFunc(data, func(match []byte) []byte {
		if allowed != nil {
			if _, ok := allowed[string(match)]; !ok {
				return match
			}
		}
		if original, ok := v.Get(string(match)); ok {
			return []byte(original)
		}
		return match
	})
}

// restoreJSONDoc decodes data as a single JSON document, reinstates tokens
// inside every string value, and re-encodes with escaping intact. Decoding
// normalizes token spans so a token is recognized whether it was rendered
// literally as <LABEL_hash> or JSON-escaped as \u003cLABEL_hash\u003e. It
// returns ok=false when data is not exactly one self-contained JSON value. When
// the document is valid JSON but nothing was restored, the original bytes are
// returned unchanged so token-free bodies are not needlessly re-encoded.
//
// Contract: when a restoration does occur the document is re-encoded, which
// normalizes formatting (object key order follows Go's map iteration and
// insignificant whitespace is dropped). The result is semantically equivalent
// but not byte-identical to the upstream bytes.
func restoreJSONDoc(data []byte, tokenRe *regexp.Regexp, allowed map[string]struct{}, v *vault) ([]byte, bool) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	r := &restorer{tokenRe: tokenRe, allowed: allowed, v: v}
	walked := r.walk(doc)
	if !r.changed {
		return data, true
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(walked); err != nil {
		return nil, false
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), true
}

func looksLikeJSON(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return false
	}
	switch trimmed[0] {
	case '{', '[', '"', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return true
	case 't':
		return bytes.HasPrefix([]byte("true"), trimmed) || bytes.HasPrefix(trimmed, []byte("true"))
	case 'f':
		return bytes.HasPrefix([]byte("false"), trimmed) || bytes.HasPrefix(trimmed, []byte("false"))
	case 'n':
		return bytes.HasPrefix([]byte("null"), trimmed) || bytes.HasPrefix(trimmed, []byte("null"))
	default:
		return false
	}
}

// isSSEData reports whether data looks like a Server-Sent Events payload with at
// least one "data:" field.
func isSSEData(data []byte) bool {
	for start := 0; start < len(data); {
		line, _, next := nextSSELine(data, start)
		if bytes.HasPrefix(line, []byte("data:")) {
			return true
		}
		start = next
	}
	return false
}

// restoreSSE restores tokens within the "data:" fields of an SSE payload,
// decoding JSON frames where possible so escaping stays valid, and preserves
// the exact line framing of everything else.
func restoreSSE(data []byte, tokenRe *regexp.Regexp, allowed map[string]struct{}, v *vault) []byte {
	var out bytes.Buffer
	out.Grow(len(data))
	for start := 0; start < len(data); {
		line, ending, next := nextSSELine(data, start)
		newLine := line
		if !bytes.HasPrefix(line, []byte("data:")) {
		} else {
			payload := line[len("data:"):]
			lead := []byte{}
			if len(payload) > 0 && payload[0] == ' ' {
				lead = []byte{' '}
				payload = payload[1:]
			}
			// Decode JSON frames first so escaped tokens (\u003c..\u003e) are
			// recognized; fall back to byte-level replacement for non-JSON frames.
			var restored []byte
			if r, ok := restoreJSONDoc(payload, tokenRe, allowed, v); ok {
				restored = r
			} else if !looksLikeJSON(payload) && tokenRe.Find(payload) != nil {
				restored = restoreRaw(payload, tokenRe, allowed, v)
			}
			if restored != nil && !bytes.Equal(restored, payload) {
				newLine = make([]byte, 0, len("data:")+len(lead)+len(restored))
				newLine = append(newLine, "data:"...)
				newLine = append(newLine, lead...)
				newLine = append(newLine, restored...)
			}
		}
		out.Write(newLine)
		out.Write(ending)
		start = next
	}
	return out.Bytes()
}

// nextSSELine returns one line without its terminator and the exact original
// terminator. SSE accepts LF, CRLF, and CR, all of which must survive rewrites.
func nextSSELine(data []byte, start int) (line, ending []byte, next int) {
	for i := start; i < len(data); i++ {
		switch data[i] {
		case '\n':
			return data[start:i], data[i : i+1], i + 1
		case '\r':
			if i+1 < len(data) && data[i+1] == '\n' {
				return data[start:i], data[i : i+2], i + 2
			}
			return data[start:i], data[i : i+1], i + 1
		}
	}
	return data[start:], nil, len(data)
}

func finalSSELineStart(data []byte) int {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '\n' || data[i] == '\r' {
			return i + 1
		}
	}
	return 0
}

func incompleteFinalSSEJSONLine(data []byte) int {
	lineStart := finalSSELineStart(data)
	line := data[lineStart:]
	if !bytes.HasPrefix(line, []byte("data:")) {
		return -1
	}
	payload := line[len("data:"):]
	if len(payload) > 0 && payload[0] == ' ' {
		payload = payload[1:]
	}
	if bytes.Equal(bytes.TrimSpace(payload), []byte("[DONE]")) || !looksLikeJSON(payload) {
		return -1
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "unexpected end of JSON input") {
			return lineStart
		}
		return -1
	}
	var trailing any
	if err := dec.Decode(&trailing); errors.Is(err, io.ErrUnexpectedEOF) {
		return lineStart
	}
	return -1
}

func incompleteFinalSSEDataPrefix(data []byte) int {
	lineStart := finalSSELineStart(data)
	line := data[lineStart:]
	if len(line) == 0 || len(line) >= len("data:") {
		return -1
	}
	if bytes.HasPrefix([]byte("data:"), line) {
		return lineStart
	}
	return -1
}

// incompleteFinalSSEEvent returns the start of a trailing SSE-shaped event that
// has not reached its blank dispatch separator. Bare JSON does not match an SSE
// field prefix, which keeps Gemini's bare-JSON stream form out of raw carry.
func incompleteFinalSSEEvent(data []byte) int {
	eventStart := 0
	hasSSEField := false
	for cursor := 0; cursor < len(data); {
		line, ending, next := nextSSELine(data, cursor)
		if len(line) == 0 && len(ending) > 0 {
			eventStart = next
			hasSSEField = false
			cursor = next
			continue
		}
		if isSSEFieldOrPrefix(line) {
			hasSSEField = true
		}
		if len(ending) == 0 {
			if hasSSEField {
				return eventStart
			}
			return -1
		}
		cursor = next
	}
	if hasSSEField && eventStart < len(data) {
		return eventStart
	}
	return -1
}

func isSSEFieldOrPrefix(line []byte) bool {
	if len(line) == 0 {
		return false
	}
	for _, field := range [][]byte{[]byte("data:"), []byte("event:"), []byte("id:"), []byte("retry:")} {
		if bytes.HasPrefix(line, field) || bytes.HasPrefix(field, line) {
			return true
		}
	}
	return false
}

// sseCarryNeedsLineBreak reports whether a newline must be re-inserted between
// carried bytes and the next chunk. Line-based upstream scanners (for example
// the Codex executor) strip the newline terminator and deliver each SSE field
// line as its own chunk, so a carried complete field line must be re-separated
// from the following field line instead of being concatenated into a single
// malformed line. It mirrors the host writer's framing so the interceptor
// reconstructs identical event bytes.
func sseCarryNeedsLineBreak(pending, chunk []byte) bool {
	if len(pending) == 0 || len(chunk) == 0 {
		return false
	}
	if bytes.HasSuffix(pending, []byte("\n")) || bytes.HasSuffix(pending, []byte("\r")) {
		return false
	}
	if chunk[0] == '\n' || chunk[0] == '\r' {
		return false
	}
	trimmed := bytes.TrimLeft(chunk, " \t")
	if len(trimmed) == 0 {
		return false
	}
	for _, prefix := range [][]byte{[]byte("data:"), []byte("event:"), []byte("id:"), []byte("retry:"), []byte(":")} {
		if bytes.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

// tokenLength returns the exact byte length of a complete token for the label:
// "<" + label + "_" + tokenHexLen hex chars + ">".
func tokenLength(label string) int {
	return len("<"+label+"_") + tokenHexLen + len(">")
}

// streamKey derives the per-stream carry key from the request body.
func streamKey(requestBody []byte) string {
	sum := sha256.Sum256(requestBody)
	return hex.EncodeToString(sum[:])
}

// resetStreamCarry drops all per-stream state for the stream (header-init call).
func resetStreamCarry(requestBody []byte) {
	streamCarry.reset(streamKey(requestBody))
}

// isTokenPrefix reports whether tail could be the beginning of a complete token
// for label: "<" then a prefix of (label + "_") then up to tokenHexLen hex chars,
// with no closing ">" yet.
func isTokenPrefix(tail []byte, label string) bool {
	s := string(tail)
	if s == "" {
		return false
	}
	full := "<" + label + "_"
	if len(s) <= len(full) {
		return strings.HasPrefix(full, s)
	}
	rest := s[len(full):]
	if len(rest) > tokenHexLen {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// incompleteTokenTail returns the number of trailing bytes of buf that may be an
// incomplete token split across a chunk boundary, bounded to tokenLen-1 bytes.
// Returns 0 when nothing needs to be withheld.
func incompleteTokenTail(buf []byte, label string, tokenLen int) int {
	start := len(buf) - (tokenLen - 1)
	if start < 0 {
		start = 0
	}
	lt := -1
	for i := len(buf) - 1; i >= start; i-- {
		if buf[i] == '<' {
			lt = i
			break
		}
	}
	if lt < 0 {
		return 0
	}
	// A closing '>' after '<' means the token (if any) is already complete.
	for i := lt + 1; i < len(buf); i++ {
		if buf[i] == '>' {
			return 0
		}
	}
	if !isTokenPrefix(buf[lt:], label) {
		return 0
	}
	return len(buf) - lt
}

func incompleteTokenTailForLabels(buf []byte, labels []string) int {
	longest := 0
	for _, label := range labels {
		if hold := incompleteTokenTail(buf, label, tokenLength(label)); hold > longest {
			longest = hold
		}
	}
	return longest
}

// detokenizeStreamChunk restores tokens in one streaming payload chunk. It
// prepends any remnant carried from the previous chunk of the same key,
// withholds a trailing incomplete-token prefix for the next chunk, and returns
// the bytes that are safe to emit now. When the entire chunk is withheld it
// returns drop=true so the caller can ask the host to drop the chunk rather
// than deliver the original (still-tokenized) bytes; the withheld bytes are
// emitted with a later chunk.
//
// Bytes still carried when the stream ends are discarded by the lifecycle end
// marker rather than emitted without a following chunk.
func detokenizeStreamChunk(key string, chunk []byte, tokenRe *regexp.Regexp, labels []string, allowed map[string]struct{}, v *vault, isSSE bool) (out []byte, drop bool) {
	mediaType := ""
	if isSSE {
		mediaType = "text/event-stream"
	}
	return detokenizeStreamChunkForMediaType(key, chunk, tokenRe, labels, allowed, v, mediaType, "")
}

func detokenizeStreamChunkForMediaType(key string, chunk []byte, tokenRe *regexp.Regexp, labels []string, allowed map[string]struct{}, v *vault, mediaType, sourceFormat string) (out []byte, drop bool) {
	isSSE := strings.EqualFold(mediaType, "text/event-stream")
	var buf []byte
	if carried := streamCarry.takeCarry(key); carried != nil {
		buf = append(buf, carried...)
		// Line-based upstream scanners strip the newline terminator and deliver
		// each SSE field line as its own chunk. Re-insert the separator so a
		// carried complete field line does not fuse with the next field line
		// into a single malformed line that never reaches a dispatch boundary.
		if isSSE && sseCarryNeedsLineBreak(buf, chunk) {
			buf = append(buf, '\n')
		}
	}
	buf = append(buf, chunk...)

	atomicResponsesEvent := false
	if isSSE && sourceFormat == formatOpenAIResponse {
		_, atomicResponsesEvent = parseAtomicSemanticSSEFrame(buf)
	}
	if saveStart := incompleteFinalSSEEvent(buf); isSSE && !atomicResponsesEvent && saveStart >= 0 {
		saved := append([]byte(nil), buf[saveStart:]...)
		if streamCarry.setCarry(key, saved) {
			buf = buf[:saveStart]
		}
	} else if saveStart := incompleteFinalSSEDataPrefix(buf); isSSE && saveStart >= 0 {
		saved := append([]byte(nil), buf[saveStart:]...)
		if streamCarry.setCarry(key, saved) {
			buf = buf[:saveStart]
		}
	} else if saveStart := incompleteFinalSSEJSONLine(buf); isSSE && saveStart >= 0 {
		saved := append([]byte(nil), buf[saveStart:]...)
		if streamCarry.setCarry(key, saved) {
			buf = buf[:saveStart]
		}
	}

	if hold := incompleteTokenTailForLabels(buf, labels); hold > 0 {
		saveStart := len(buf) - hold
		lineStart := finalSSELineStart(buf[:saveStart])
		if isSSE && bytes.HasPrefix(buf[lineStart:], []byte("data:")) {
			saveStart = lineStart
		}
		saved := make([]byte, len(buf)-saveStart)
		copy(saved, buf[saveStart:])
		if streamCarry.setCarry(key, saved) {
			buf = buf[:saveStart]
		}
	}
	if len(buf) == 0 {
		return nil, true
	}
	if restored, handled := restoreSemanticStream(key, buf, tokenRe, labels, allowed, v, mediaType, sourceFormat); handled {
		return restored, false
	}
	return restoreBodyForMediaType(buf, tokenRe, allowed, v, mediaType), false
}
