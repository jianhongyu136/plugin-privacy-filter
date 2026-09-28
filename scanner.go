package main

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const scanContextMaxRunes = 160
const diagnosticPlaceholder = "[REDACTED]"

var diagnosticTokenRe = restoreTokenPattern()
var diagnosticPlaceholderRe = regexp.MustCompile(`\[REDACTED\]`)

// scanMatch records a redaction. Only identifiable rule-matched field names
// enter diagnostics; Context never stores block plaintext.
type scanMatch struct {
	Rule          string
	RuleType      string // "field" or "value"
	Path          string
	Field         string
	Fields        []string // additional names from multiple config assignments in one string
	OmittedFields int
	Context       string
	Excerpt       string // bounded nearby text with all recognized tokens masked
}

// scanResult is the outcome of scanning a request body.
type scanResult struct {
	Body            []byte
	Matches         []scanMatch
	ReadOnlyMatches []scanMatch
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
	rules                ruleSet
	tokenRe              tokenMatcher
	redact               redactFunc
	stopAfterFirst       bool
	matches              []scanMatch
	readOnlyMatches      []scanMatch
	warnInvalidArguments func(path, detail string, matches []scanMatch)
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
					v[key] = s.redactWhole(str, rule.name, childPath, key)
					continue
				}
				v[key] = s.scanText(str, childPath)
				continue
			}
			// Non-string values (numbers, booleans, objects, arrays) are still
			// redacted whole when the field name matches a rule; otherwise a
			// sensitive value such as {"password": 123456} would leak.
			if rule, matched := s.matchFieldRuleNonString(key); matched {
				v[key] = s.redactWholeValue(child, rule.name, childPath, key)
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
func (s *scanner) redactWhole(value, ruleName, path, key string) string {
	if s.isWholeToken(value) {
		return value
	}
	token := s.redact(value)
	s.recordMatch(scanMatch{Rule: ruleName, RuleType: "field", Path: path, Field: diagnosticField(key), Context: token, Excerpt: fieldDiagnosticExcerpt(key)})
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
func (s *scanner) redactWholeValue(value any, ruleName, path, key string) any {
	raw, err := json.Marshal(value)
	if err != nil {
		// Unreachable for a value decoded from JSON; keep the original rather
		// than dropping content.
		return value
	}
	token := s.redact(string(raw))
	s.recordMatch(scanMatch{Rule: ruleName, RuleType: "field", Path: path, Field: diagnosticField(key), Context: token, Excerpt: fieldDiagnosticExcerpt(key)})
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

// valueRuleSpan applies the same capture-group and validator semantics to both
// replacement and read-only detection. Group 1 selects the sensitive fragment;
// an unmatched optional group falls back to the whole match.
func valueRuleSpan(r valueRule, text string, match []int) (start, end int, valid bool) {
	start, end = match[0], match[1]
	if r.re.NumSubexp() >= 1 && match[2] >= 0 {
		start, end = match[2], match[3]
	}
	return start, end, end > start && (r.validate == nil || r.validate(text[start:end]))
}

// detectText runs value rules without replacements or token creation. Invalid
// JSON has no reliable field-name structure, so field rules do not apply. One
// finding is recorded per matching rule; block mode stops at the first finding.
func (s *scanner) detectText(text, path string) []scanMatch {
	if len(s.rules.valueRules) == 0 {
		return nil
	}
	var segments []string
	last := 0
	if s.tokenRe != nil {
		for _, span := range s.tokenRe.FindAllStringIndex(text, -1) {
			if span[0] > last {
				segments = append(segments, text[last:span[0]])
			}
			last = span[1]
		}
	}
	if last < len(text) {
		segments = append(segments, text[last:])
	}
	var findings []scanMatch
nextRule:
	for _, rule := range s.rules.valueRules {
		for _, segment := range segments {
			for _, match := range rule.re.FindAllStringSubmatchIndex(segment, -1) {
				_, _, valid := valueRuleSpan(rule, segment, match)
				if !valid {
					continue
				}
				findings = append(findings, scanMatch{
					Rule: rule.name, RuleType: "value", Path: path,
					Field: diagnosticField(configFieldName(rule, segment, match)), Context: "[redacted]",
				})
				if s.stopAfterFirst {
					return findings
				}
				continue nextRule
			}
		}
	}
	return findings
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
		var fields []string
		var omittedFields int
		var next []textSegment
		for _, segment := range segments {
			if segment.protected {
				next = append(next, segment)
				continue
			}
			matches := r.re.FindAllStringSubmatchIndex(segment.value, -1)
			if len(matches) == 0 {
				next = append(next, segment)
				continue
			}
			last := 0
			for _, match := range matches {
				if match[0] > last {
					next = append(next, textSegment{value: segment.value[last:match[0]]})
				}
				last = match[1]
				rs, re, valid := valueRuleSpan(r, segment.value, match)
				whole := segment.value[match[0]:match[1]]
				fragment := segment.value[rs:re]
				if !valid {
					next = append(next, textSegment{value: whole})
					continue
				}
				fired = true
				if rs > match[0] {
					next = append(next, textSegment{value: segment.value[match[0]:rs]})
				}
				token := s.redact(fragment)
				if s.stopAfterFirst {
					s.recordMatch(scanMatch{Rule: r.name, RuleType: "value", Path: path, Field: diagnosticField(configFieldName(r, segment.value, match)), Context: token,
						Excerpt: s.diagnosticTextExcerpt(text, path, fragment)})
				}
				if !s.stopAfterFirst && r.hasConfigKey {
					field := diagnosticField(configFieldName(r, segment.value, match))
					if field != "" {
						seen := false
						for _, existing := range fields {
							if existing == field {
								seen = true
								break
							}
						}
						if !seen {
							if len(fields) < scanLogMaxPaths {
								fields = append(fields, field)
							} else {
								omittedFields++
							}
						}
					}
				}
				if firstToken == "" {
					firstToken = token
				}
				next = append(next, textSegment{value: token, protected: true})
				if re < match[1] {
					next = append(next, textSegment{value: segment.value[re:match[1]]})
				}
			}
			if last < len(segment.value) {
				next = append(next, textSegment{value: segment.value[last:]})
			}
		}
		segments = next
		if fired {
			matchIndex := s.recordMatch(scanMatch{Rule: r.name, RuleType: "value", Path: path, Fields: fields, OmittedFields: omittedFields})
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
		s.matches[item.matchIndex].Excerpt = diagnosticExcerpt(text, item.token)
	}
	return text
}

// diagnosticTextExcerpt performs a read-only diagnostic pass over the string.
// This masks *all* known value-rule hits, even though block mode stopped after
// its first finding. It never calls the token-writing redactor or writes a vault.
func (s *scanner) diagnosticTextExcerpt(text, path, fragment string) string {
	// Keep block-mode diagnostics from rescanning an unbounded request string.
	if len(text) > 64*1024 {
		return diagnosticPlaceholder
	}
	redact := func(value string) string { return makeToken("DIAG", value) }
	// Do not let a value rule reveal part of an existing or forged token.
	withoutTokens := diagnosticTokenRe.ReplaceAllString(text, diagnosticPlaceholder)
	preview := &scanner{rules: s.rules, tokenRe: diagnosticPlaceholderRe, redact: redact}
	masked := preview.scanText(withoutTokens, path)
	if excerpt := diagnosticExcerpt(masked, redact(fragment)); excerpt != "" {
		return excerpt
	}
	return diagnosticPlaceholder
}

// diagnosticExcerpt replaces tokens before taking the bounded window so an
// excerpt boundary cannot leave part of a token or its hash in a log.
func diagnosticExcerpt(text, focus string) string {
	index := strings.Index(text, focus)
	if index < 0 {
		return ""
	}
	prefix := diagnosticTokenRe.ReplaceAllString(text[:index], diagnosticPlaceholder)
	suffix := diagnosticTokenRe.ReplaceAllString(text[index+len(focus):], diagnosticPlaceholder)
	masked := prefix + diagnosticPlaceholder + suffix
	masked = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, masked)
	return redactedExcerptAt(masked, utf8.RuneCountInString(prefix), utf8.RuneCountInString(diagnosticPlaceholder))
}

func fieldDiagnosticExcerpt(key string) string {
	quoted, _ := json.Marshal(diagnosticField(key))
	return string(quoted) + ": " + strconv.Quote(diagnosticPlaceholder)
}

// diagnosticField bounds and sanitizes an identifiable rule-matched key.
// Keys from unrelated runtime objects are never added to match metadata.
func diagnosticField(key string) string {
	runes := []rune(key)
	if len(runes) > 80 {
		runes = append(runes[:77], '.', '.', '.')
	}
	for i, r := range runes {
		if r < 32 || r == 127 {
			runes[i] = ' '
		}
	}
	return string(runes)
}

// configFieldName extracts the assignment key preceding capture group 1 only
// from builtin config_* rules. It never inspects or returns the captured value.
func configFieldName(rule valueRule, text string, match []int) string {
	if !rule.hasConfigKey || len(match) < 4 || match[2] < match[0] || match[3] <= match[2] {
		return ""
	}
	prefix := strings.TrimSpace(text[match[0]:match[2]])
	if len(prefix) < 2 || (prefix[len(prefix)-1] != '=' && prefix[len(prefix)-1] != ':') {
		return ""
	}
	key := strings.TrimSpace(prefix[:len(prefix)-1])
	if key == "" {
		return ""
	}
	for _, c := range key {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return ""
		}
	}
	return key
}

func redactedExcerpt(text, focus string) string {
	start, length := 0, 0
	if byteIndex := strings.Index(text, focus); byteIndex >= 0 {
		start = utf8.RuneCountInString(text[:byteIndex])
		length = utf8.RuneCountInString(focus)
	}
	return redactedExcerptAt(text, start, length)
}

func redactedExcerptAt(text string, focusStart, focusLen int) string {
	runes := []rune(text)
	if len(runes) <= scanContextMaxRunes {
		return text
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

// joinDynamicKey masks request-controlled object keys in paths. Only an
// explicitly matched field-rule key is exposed separately as a bounded name.
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
