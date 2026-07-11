package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

const scanContextMaxRunes = 160

// scanMatch records a single redaction. Context is derived only from the final
// redacted value; it never contains the matched plaintext.
type scanMatch struct {
	Rule     string
	RuleType string // "field" or "value"
	Path     string
	Context  string
}

// scanResult is the outcome of scanning a request body.
type scanResult struct {
	Body    []byte
	Matches []scanMatch
}

// redactFunc returns the replacement token for an original secret and is
// responsible for persisting the token->original mapping (see tokenizer.go).
type redactFunc func(original string) string

// tokenMatcher matches an already-emitted token span so existing tokens are
// left untouched (idempotency across the before-auth + after-auth stages and
// after-auth retries). *regexp.Regexp satisfies this interface.
type tokenMatcher interface {
	MatchString(string) bool
	FindString(string) string
	FindAllStringIndex(string, int) [][]int
}

type scanner struct {
	rules          ruleSet
	tokenRe        tokenMatcher
	redact         redactFunc
	stopAfterFirst bool
	matches        []scanMatch
}

type blockScanStopped struct{}

func (s *scanner) recordMatch(match scanMatch) int {
	s.matches = append(s.matches, match)
	index := len(s.matches) - 1
	if s.stopAfterFirst {
		// The block-only scan boundary recovers this private sentinel to unwind
		// provider-specific traversal immediately, without changing every scanner
		// function signature solely to propagate a stop result.
		panic(blockScanStopped{})
	}
	return index
}

// walk recurses through decoded JSON. Objects: a field-name rule match on the
// key replaces the whole string value with a token; other string values get
// value-pattern fragment scanning. Arrays and nested objects recurse.
func (s *scanner) walk(node any, path string) any {
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			childPath := joinDynamicKey(path)
			if str, ok := child.(string); ok {
				if rule, matched := s.matchFieldRule(key, str); matched {
					v[key] = s.redactWhole(str, rule.name, childPath)
					continue
				}
				v[key] = s.scanText(str, childPath)
				continue
			}
			// Non-string values (numbers, booleans, objects, arrays) are still
			// redacted whole when the field name matches a rule; otherwise a
			// sensitive value such as {"password": 123456} would leak.
			if rule, matched := s.matchFieldRuleNonString(key); matched {
				v[key] = s.redactWholeValue(child, rule.name, childPath)
				continue
			}
			v[key] = s.walk(child, childPath)
		}
		return v
	case []any:
		for i, child := range v {
			childPath := path + "[" + strconv.Itoa(i) + "]"
			if str, ok := child.(string); ok {
				v[i] = s.scanText(str, childPath)
				continue
			}
			v[i] = s.walk(child, childPath)
		}
		return v
	default:
		return node
	}
}

// matchFieldRule reports the first field rule whose key set contains key
// (case-insensitive) and whose optional valueConstraint permits the value.
func (s *scanner) matchFieldRule(key, value string) (fieldRule, bool) {
	lower := toLower(key)
	for _, r := range s.rules.fieldRules {
		if _, ok := r.keys[lower]; !ok {
			continue
		}
		if r.valueConstraint != nil && !r.valueConstraint.MatchString(value) {
			continue
		}
		return r, true
	}
	return fieldRule{}, false
}

// matchFieldRuleNonString reports the first field rule whose key set contains
// key (case-insensitive) and that has no value constraint. A value constraint
// is a string pattern and cannot be evaluated against a non-string value, so
// constrained rules are skipped here.
func (s *scanner) matchFieldRuleNonString(key string) (fieldRule, bool) {
	lower := toLower(key)
	for _, r := range s.rules.fieldRules {
		if _, ok := r.keys[lower]; !ok {
			continue
		}
		if r.valueConstraint != nil {
			continue
		}
		return r, true
	}
	return fieldRule{}, false
}

// redactWhole replaces an entire value with a token, unless the value is
// itself exactly one complete token. The match must span the whole value: a
// value that merely contains a token substring (for example a forged
// "hunter2 <REDACTED_0000000000000000>") still carries a secret and must be
// redacted. Records a "field" match.
func (s *scanner) redactWhole(value, ruleName, path string) string {
	if s.isWholeToken(value) {
		return value
	}
	token := s.redact(value)
	s.recordMatch(scanMatch{Rule: ruleName, RuleType: "field", Path: path, Context: token})
	return token
}

// redactWholeValue replaces a non-string value (number, bool, object, array)
// with a token derived from its canonical JSON encoding. Records a "field"
// match.
//
// Contract: the value is stored and restored as the string form of its JSON
// encoding, so a non-string secret changes JSON type on the round trip (for
// example {"password": 123456} restores as {"password": "123456"}). This
// preserves the secret's characters but not its original JSON kind; callers
// that need the exact original type must not route such fields through the
// filter.
func (s *scanner) redactWholeValue(value any, ruleName, path string) any {
	raw, err := json.Marshal(value)
	if err != nil {
		// Unreachable for a value decoded from JSON; keep the original rather
		// than dropping content.
		return value
	}
	token := s.redact(string(raw))
	s.recordMatch(scanMatch{Rule: ruleName, RuleType: "field", Path: path, Context: token})
	return token
}

// isWholeToken reports whether value is exactly one complete token with no
// surrounding content.
func (s *scanner) isWholeToken(value string) bool {
	if s.tokenRe == nil || value == "" {
		return false
	}
	return s.tokenRe.FindString(value) == value
}

// scanText applies every value rule as a fragment replacement over text,
// leaving any existing token spans untouched so a custom rule cannot rewrite
// the inside of a token (its label or hex) and corrupt it. Records one "value"
// match per rule that fires (regardless of how many fragments it replaced).
func (s *scanner) scanText(text, path string) string {
	if s.tokenRe == nil {
		return s.applyValueRules(text, path)
	}
	spans := s.tokenRe.FindAllStringIndex(text, -1)
	if len(spans) == 0 {
		return s.applyValueRules(text, path)
	}
	var out bytes.Buffer
	last := 0
	for _, sp := range spans {
		out.WriteString(s.applyValueRules(text[last:sp[0]], path))
		out.WriteString(text[sp[0]:sp[1]]) // keep the existing token verbatim
		last = sp[1]
	}
	out.WriteString(s.applyValueRules(text[last:], path))
	return out.String()
}

// applyValueRules runs every value rule over a token-free text segment.
func (s *scanner) applyValueRules(text, path string) string {
	type textSegment struct {
		value     string
		protected bool
	}
	type pendingContext struct {
		matchIndex int
		token      string
	}
	segments := []textSegment{{value: text}}
	var pending []pendingContext
	for _, r := range s.rules.valueRules {
		var fired bool
		var firstToken string
		var next []textSegment
		for _, segment := range segments {
			if segment.protected {
				next = append(next, segment)
				continue
			}
			matches := r.re.FindAllStringIndex(segment.value, -1)
			if len(matches) == 0 {
				next = append(next, segment)
				continue
			}
			last := 0
			for _, match := range matches {
				if match[0] > last {
					next = append(next, textSegment{value: segment.value[last:match[0]]})
				}
				fragment := segment.value[match[0]:match[1]]
				if r.validate != nil && !r.validate(fragment) {
					next = append(next, textSegment{value: fragment})
				} else {
					fired = true
					token := s.redact(fragment)
					if s.stopAfterFirst {
						s.recordMatch(scanMatch{Rule: r.name, RuleType: "value", Path: path, Context: token})
					}
					if firstToken == "" {
						firstToken = token
					}
					next = append(next, textSegment{value: token, protected: true})
				}
				last = match[1]
			}
			if last < len(segment.value) {
				next = append(next, textSegment{value: segment.value[last:]})
			}
		}
		segments = next
		if fired {
			matchIndex := s.recordMatch(scanMatch{Rule: r.name, RuleType: "value", Path: path})
			pending = append(pending, pendingContext{matchIndex: matchIndex, token: firstToken})
		}
	}
	var out strings.Builder
	for _, segment := range segments {
		out.WriteString(segment.value)
	}
	text = out.String()
	// Populate contexts only after every rule has run. This prevents a context
	// for an early rule from retaining plaintext that a later rule redacts.
	for _, item := range pending {
		s.matches[item.matchIndex].Context = redactedExcerpt(text, item.token)
	}
	return text
}

func redactedExcerpt(text, focus string) string {
	runes := []rune(text)
	if len(runes) <= scanContextMaxRunes {
		return text
	}
	focusStart, focusLen := 0, 0
	if byteIndex := strings.Index(text, focus); byteIndex >= 0 {
		focusStart = utf8.RuneCountInString(text[:byteIndex])
		focusLen = utf8.RuneCountInString(focus)
	}
	window := func(size int) (int, int) {
		start := focusStart - (size-focusLen)/2
		if start < 0 {
			start = 0
		}
		if start+size > len(runes) {
			start = len(runes) - size
		}
		return start, start + size
	}

	// Reserve both ellipses first. If the focused window touches one edge, use
	// that freed marker space for three more source characters.
	start, end := window(scanContextMaxRunes - 6)
	if start == 0 {
		start, end = 0, scanContextMaxRunes-3
	} else if end == len(runes) {
		start, end = len(runes)-(scanContextMaxRunes-3), len(runes)
	}
	prefix, suffix := "", ""
	if start > 0 {
		prefix = "..."
	}
	if end < len(runes) {
		suffix = "..."
	}
	return prefix + string(runes[start:end]) + suffix
}

// joinDynamicKey appends a fixed marker for a request-controlled object key.
// The real key is still used for field-rule matching, but never enters
// diagnostics or logs where it could disclose request content.
func joinDynamicKey(path string) string {
	if path == "" {
		return ".*"
	}
	return path + ".*"
}

// toLower lowercases ASCII without allocating for the common all-lower case.
func toLower(s string) string {
	need := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			need = true
			break
		}
	}
	if !need {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// replaceAllFunc replaces every non-overlapping match of re in src with the
// result of repl, preserving the text between matches.
func replaceAllFunc(src string, re interface{ FindAllStringIndex(string, int) [][]int }, repl func(string) string) string {
	idx := re.FindAllStringIndex(src, -1)
	if len(idx) == 0 {
		return src
	}
	var out bytes.Buffer
	last := 0
	for _, pair := range idx {
		out.WriteString(src[last:pair[0]])
		out.WriteString(repl(src[pair[0]:pair[1]]))
		last = pair[1]
	}
	out.WriteString(src[last:])
	return out.String()
}
