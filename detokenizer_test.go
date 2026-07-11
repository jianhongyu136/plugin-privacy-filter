package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

func detokTestSetup() (string, *regexp.Regexp) {
	setSharedVault(newVault(100, time.Hour))
	label := "REDACTED"
	return label, tokenPattern(label)
}

func TestRestoreTokensLeavesUnknown(t *testing.T) {
	label, tokenRe := detokTestSetup()
	token := makeToken(label, "never-stored")
	// deliberately NOT Put into the vault
	body := []byte("value=" + token)
	out := string(restoreBody(body, tokenRe, nil, getSharedVault()))
	if out != "value="+token {
		t.Fatalf("unknown token should be left verbatim, got %q", out)
	}
}

func TestTokenLength(t *testing.T) {
	if got := tokenLength("REDACTED"); got != 27 {
		t.Fatalf("tokenLength(REDACTED) = %d, want 27", got)
	}
}

func TestIsTokenPrefix(t *testing.T) {
	label := "REDACTED"
	cases := []struct {
		in   string
		want bool
	}{
		{"<", true},
		{"<RED", true},
		{"<REDACTED_", true},
		{"<REDACTED_1a2b", true},
		{"<div", false},
		{"<REDACTED_z", false},                 // z is not hex
		{"<REDACTED_00000000000000000", false}, // 17 hex, too long
	}
	for _, c := range cases {
		if got := isTokenPrefix([]byte(c.in), label); got != c.want {
			t.Fatalf("isTokenPrefix(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestDetokenizeStreamSplitToken(t *testing.T) {
	label, tokenRe := detokTestSetup()
	original := "sk-abcdefghij0123456789"
	token := makeToken(label, original)
	getSharedVault().Put(token, original)

	req := []byte(`{"model":"x"}`)
	key := streamKey(req)

	half := len(token) / 2
	chunk1 := []byte("prefix " + token[:half])
	chunk2 := []byte(token[half:] + " suffix")

	out1b, _ := detokenizeStreamChunk(key, chunk1, tokenRe, []string{label}, nil, getSharedVault(), false)
	out1 := string(out1b)
	if !strings.Contains(out1, "prefix ") {
		t.Fatalf("out1 missing prefix: %q", out1)
	}
	if strings.Contains(out1, original) {
		t.Fatalf("out1 restored too early: %q", out1)
	}

	out2b, _ := detokenizeStreamChunk(key, chunk2, tokenRe, []string{label}, nil, getSharedVault(), false)
	out2 := string(out2b)
	combined := out1 + out2
	if !strings.Contains(combined, original) {
		t.Fatalf("combined did not restore original: %q", combined)
	}
	if strings.Contains(combined, token) {
		t.Fatalf("combined still contains raw token: %q", combined)
	}
}

func TestDetokenizeStreamNoFalseWithhold(t *testing.T) {
	label, tokenRe := detokTestSetup()
	req := []byte(`{"model":"y"}`)
	key := streamKey(req)

	chunk := []byte("<div>hello</div>")
	outb, _ := detokenizeStreamChunk(key, chunk, tokenRe, []string{label}, nil, getSharedVault(), false)
	out := string(outb)
	if out != "<div>hello</div>" {
		t.Fatalf("non-token content should pass through unchanged, got %q", out)
	}
}

func TestStreamAllowlistCachedPerStream(t *testing.T) {
	streamCarry.reset("k1")
	streamCarry.reset("k2")

	calls := 0
	build := func() map[string]struct{} {
		calls++
		return map[string]struct{}{"<REDACTED_1a2b3c4d5e6f7a8b>": {}}
	}

	// Repeated chunks of the same stream must reuse the cached allowlist.
	streamCarry.allowlist("k1", build)
	streamCarry.allowlist("k1", build)
	streamCarry.allowlist("k1", build)
	if calls != 1 {
		t.Fatalf("allowlist built %d times for one stream, want 1", calls)
	}

	// A different stream computes its own allowlist.
	streamCarry.allowlist("k2", build)
	if calls != 2 {
		t.Fatalf("allowlist built %d times across two streams, want 2", calls)
	}

	// Resetting the stream discards the cache; the next use rebuilds.
	streamCarry.reset("k1")
	streamCarry.allowlist("k1", build)
	if calls != 3 {
		t.Fatalf("allowlist built %d times after reset, want 3", calls)
	}
}

func TestCollectTokensRequiresVaultMappingAndIsBounded(t *testing.T) {
	tokenRe := restoreTokenPattern()
	v := newVault(streamAllowlistMaxTokens+10, time.Hour)
	var request strings.Builder
	request.WriteString(`<FORGED_0000000000000000>`)
	for i := 0; i < streamAllowlistMaxTokens+1; i++ {
		original := "secret-" + itoa(i)
		token := makeToken("L"+itoa(i), original)
		v.Put(token, original)
		request.WriteString(token)
	}

	allowed := collectTokens([]byte(request.String()), tokenRe, v)
	if _, ok := allowed[`<FORGED_0000000000000000>`]; ok {
		t.Fatal("forged token without a vault mapping entered the allowlist")
	}
	if len(allowed) != streamAllowlistMaxTokens {
		t.Fatalf("allowlist size = %d, want bounded size %d", len(allowed), streamAllowlistMaxTokens)
	}
	if labels := tokenLabels(allowed); len(labels) > streamAllowlistMaxTokens {
		t.Fatalf("token label count = %d, exceeds bound %d", len(labels), streamAllowlistMaxTokens)
	}
	for token := range allowed {
		if _, ok := v.Get(token); !ok {
			t.Fatalf("allowlist contains token without a vault mapping: %q", token)
		}
	}
}

func TestCollectTokensFindsJSONEscapedMappedTokens(t *testing.T) {
	tokenRe := restoreTokenPattern()
	v := newVault(10, time.Hour)
	token := makeToken("REDACTED", "secret")
	v.Put(token, "secret")
	request, err := json.Marshal(map[string]any{"value": token})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	escaped := strings.ReplaceAll(strings.ReplaceAll(string(request), "<", `\u003c`), ">", `\u003e`)
	allowed := collectTokens([]byte(escaped), tokenRe, v)
	if _, ok := allowed[token]; !ok {
		t.Fatalf("JSON-escaped mapped token missing from allowlist: request=%q allowed=%v", escaped, allowed)
	}
}

func TestResetStreamCarry(t *testing.T) {
	label, tokenRe := detokTestSetup()
	req := []byte(`{"model":"z"}`)
	key := streamKey(req)

	// Leave a remnant behind.
	partial := []byte("<REDACTED_1a2b")
	detokenizeStreamChunk(key, partial, tokenRe, []string{label}, nil, getSharedVault(), false)
	if !streamCarry.has(key) {
		t.Fatalf("expected a carried remnant")
	}
	resetStreamCarry(req)
	if streamCarry.has(key) {
		t.Fatalf("resetStreamCarry did not clear the remnant")
	}
}

func TestStreamStoreCapacityEvictsLeastRecentlyUsed(t *testing.T) {
	store := newStreamStore()
	for i := 0; i < streamCarryMaxEntries; i++ {
		key := "key-" + itoa(i)
		store.allowlist(key, func() map[string]struct{} { return map[string]struct{}{} })
	}
	store.allowlist("key-0", func() map[string]struct{} { return nil })
	store.allowlist("overflow", func() map[string]struct{} { return map[string]struct{}{} })
	if !store.has("key-0") {
		t.Fatal("recently touched entry was evicted")
	}
	if store.has("key-1") {
		t.Fatal("least recently used entry was not evicted")
	}
}

func TestStreamStoreGlobalByteBudgetEvictsLeastRecentlyUsed(t *testing.T) {
	store := newStreamStoreWithLimits(time.Minute, 12)
	if !store.setCarry("old", []byte("12345678")) {
		t.Fatal("first carry was unexpectedly rejected")
	}
	if !store.setCarry("new", []byte("abcdefgh")) {
		t.Fatal("second carry was unexpectedly rejected")
	}
	if store.has("old") {
		t.Fatal("least recently used carry was not evicted for global byte budget")
	}
	if !store.has("new") {
		t.Fatal("new carry was evicted instead of old carry")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.totalBytes > store.maxBytes {
		t.Fatalf("stream state bytes = %d, exceeds budget %d", store.totalBytes, store.maxBytes)
	}
}

func TestStreamStoreByteAccountingIncludesContentChannelNames(t *testing.T) {
	store := newStreamStore()
	key := "stream"
	channel := "openai:choice:0"
	pending := "<REDACTED_1a2b"

	store.mu.Lock()
	entry := store.getOrCreateLocked(key, time.Now())
	entry.content = map[string]string{channel: pending}
	store.resizeEntryLocked(entry)
	entryBytes := entry.bytes
	totalBytes := store.totalBytes
	store.mu.Unlock()

	want := len(key) + len(channel) + len(pending)
	if entryBytes != want || totalBytes != want {
		t.Fatalf("content state bytes: entry=%d total=%d, want %d including channel name", entryBytes, totalBytes, want)
	}
}

func TestStreamStoreCleanupRemovesIdleState(t *testing.T) {
	store := newStreamStoreWithLimits(20*time.Millisecond, streamStoreMaxBytes)
	store.startCleanup()
	defer store.stopCleanup()
	if !store.setCarry("idle", []byte("held")) {
		t.Fatal("carry was unexpectedly rejected")
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		_, exists := store.entries["idle"]
		store.mu.Unlock()
		if !exists {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("idle stream state was not proactively removed")
}

func TestPluginShutdownClearsStreamState(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	streamCarry.clear()
	if !streamCarry.setCarry("shutdown", []byte("held")) {
		t.Fatal("carry was unexpectedly rejected")
	}
	pluginShutdown()
	streamCarry.mu.Lock()
	remaining := len(streamCarry.entries)
	streamCarry.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("plugin shutdown retained %d stream entries", remaining)
	}
	callRegister(t, pluginabi.MethodPluginRegister, "")
}

func BenchmarkStreamStoreAllowlistEmpty(b *testing.B) {
	store := newStreamStore()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.allowlist("active", func() map[string]struct{} { return map[string]struct{}{} })
	}
}

func BenchmarkStreamStoreAllowlistFull(b *testing.B) {
	store := newStreamStore()
	for i := 0; i < streamCarryMaxEntries; i++ {
		key := "key-" + itoa(i)
		store.allowlist(key, func() map[string]struct{} { return map[string]struct{}{} })
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.allowlist("key-0", func() map[string]struct{} { return map[string]struct{}{} })
	}
}
