package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// testTokenRe matches the <LABEL_hex> token span used by tests.
var testTokenRe = regexp.MustCompile(`<REDACTED_[0-9a-f]{16}>`)

// testRedact is a deterministic stand-in for the Task 5 tokenizer: it wraps the
// original in a recognizable, fixed-length token without touching a real vault.
func testRedact(original string) string {
	// Not a real hash; the scanner only needs a stable replacement string.
	sum := 0
	for _, r := range original {
		sum = (sum*31 + int(r)) & 0xffffffff
	}
	return "<REDACTED_" + strings.Repeat("0", 8) + reHex(sum) + ">"
}

func reHex(n int) string {
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		buf[i] = hexDigits[n&0xf]
		n >>= 4
	}
	return string(buf)
}

func testRules() ruleSet {
	return compileRules(true, nil, nil, nil, nil)
}

func scanJSONObjectForTest(t *testing.T, body []byte, rules ruleSet, tokenRe tokenMatcher, redact redactFunc) scanResult {
	t.Helper()
	doc, ok := decodeJSONObject(body)
	if !ok {
		t.Fatalf("test body is not exactly one JSON object: %s", body)
	}
	s := &scanner{rules: rules, tokenRe: tokenRe, redact: redact}
	walked := s.walk(doc, "")
	if len(s.matches) == 0 {
		return scanResult{Body: body}
	}
	return scanResult{Body: reencodeJSON(walked, body), Matches: s.matches}
}

func TestScanFieldNameReplacesWholeValue(t *testing.T) {
	body := []byte(`{"password":"hunter2","note":"hello"}`)
	res := scanJSONObjectForTest(t, body, testRules(), testTokenRe, testRedact)
	var out map[string]any
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	if out["password"] == "hunter2" {
		t.Fatalf("password not redacted: %v", out["password"])
	}
	if !testTokenRe.MatchString(out["password"].(string)) {
		t.Fatalf("password value is not a token: %v", out["password"])
	}
	if out["note"] != "hello" {
		t.Fatalf("note should be untouched: %v", out["note"])
	}
	if len(res.Matches) != 1 || res.Matches[0].RuleType != "field" || res.Matches[0].Rule != "password" {
		t.Fatalf("unexpected matches: %+v", res.Matches)
	}
	if res.Matches[0].Path != ".*" {
		t.Fatalf("unexpected path: %q", res.Matches[0].Path)
	}
}

func TestScanValuePatternFragmentReplace(t *testing.T) {
	body := []byte(`{"note":"my key is sk-abcdefghij0123456789 ok"}`)
	res := scanJSONObjectForTest(t, body, testRules(), testTokenRe, testRedact)
	var out map[string]any
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	note := out["note"].(string)
	if strings.Contains(note, "sk-abcdefghij0123456789") {
		t.Fatalf("secret fragment not redacted: %q", note)
	}
	if !strings.HasPrefix(note, "my key is ") || !strings.HasSuffix(note, " ok") {
		t.Fatalf("surrounding text should be preserved: %q", note)
	}
	if len(res.Matches) != 1 || res.Matches[0].RuleType != "value" || res.Matches[0].Rule != "openai_key" {
		t.Fatalf("unexpected matches: %+v", res.Matches)
	}
}

func TestScanRecursesArraysAndObjects(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"token=access_here"},{"api_key":"AKIABCDEFGHIJKLMNOP"}]}`)
	res := scanJSONObjectForTest(t, body, testRules(), testTokenRe, testRedact)
	if len(res.Matches) == 0 {
		t.Fatalf("expected matches in nested structures")
	}
	foundField := false
	for _, m := range res.Matches {
		if m.Rule == "api_key" && m.RuleType == "field" && m.Path == ".*[1].*" {
			foundField = true
		}
	}
	if !foundField {
		t.Fatalf("expected nested field match with sanitized path .*[1].*: %+v", res.Matches)
	}
}

func TestScanSkipsAlreadyTokenized(t *testing.T) {
	body := []byte(`{"password":"<REDACTED_0000000012345678>"}`)
	res := scanJSONObjectForTest(t, body, testRules(), testTokenRe, testRedact)
	var out map[string]any
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	if out["password"] != "<REDACTED_0000000012345678>" {
		t.Fatalf("already-tokenized value should be untouched: %v", out["password"])
	}
	if len(res.Matches) != 0 {
		t.Fatalf("expected no matches for already-tokenized value: %+v", res.Matches)
	}
}

func TestRedactedExcerptMaximumIncludesEllipses(t *testing.T) {
	focus := "<BLOCKED_0000000000000000>"
	context := redactedExcerpt(strings.Repeat("x", 220)+focus+strings.Repeat("y", 220), focus)
	if got := utf8.RuneCountInString(context); got > scanContextMaxRunes {
		t.Fatalf("context length = %d runes, exceeds %d: %q", got, scanContextMaxRunes, context)
	}
	if !strings.HasPrefix(context, "...") || !strings.HasSuffix(context, "...") || !strings.Contains(context, focus) {
		t.Fatalf("context did not preserve bounded focus window: %q", context)
	}
}

func TestValueRuleCaptureGroupPreservesPrefix(t *testing.T) {
	rules := compileRules(false, nil, nil, nil, []customValueRule{
		{Name: "kv_secret", Regex: `(?i)password\s*[:=]\s*(\S+)`},
	})
	body := []byte(`{"note":"password: hunter2secret here"}`)
	res := scanJSONObjectForTest(t, body, rules, testTokenRe, testRedact)
	var out map[string]any
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	note := out["note"].(string)
	if strings.Contains(note, "hunter2secret") {
		t.Fatalf("captured secret not redacted: %q", note)
	}
	if !strings.HasPrefix(note, "password: ") {
		t.Fatalf("prefix should be preserved verbatim: %q", note)
	}
	if !strings.HasSuffix(note, " here") {
		t.Fatalf("suffix should be preserved verbatim: %q", note)
	}
	if !strings.Contains(note, testRedact("hunter2secret")) {
		t.Fatalf("only the captured group should be tokenized: %q", note)
	}
	if len(res.Matches) != 1 || res.Matches[0].Rule != "kv_secret" || res.Matches[0].RuleType != "value" {
		t.Fatalf("unexpected matches: %+v", res.Matches)
	}
}

func TestValueRuleWithoutCaptureGroupReplacesWholeMatch(t *testing.T) {
	rules := compileRules(false, nil, nil, nil, []customValueRule{
		{Name: "whole", Regex: `password\s*[:=]\s*\S+`},
	})
	body := []byte(`{"note":"password: hunter2 here"}`)
	res := scanJSONObjectForTest(t, body, rules, testTokenRe, testRedact)
	var out map[string]any
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	note := out["note"].(string)
	if strings.Contains(note, "password: hunter2") {
		t.Fatalf("whole match should be redacted: %q", note)
	}
	if !strings.HasPrefix(note, testRedact("password: hunter2")) {
		t.Fatalf("whole match should become a single token: %q", note)
	}
	if !strings.HasSuffix(note, " here") {
		t.Fatalf("suffix should be preserved: %q", note)
	}
}

func TestBuiltinConfigRulesDetectYAMLSecrets(t *testing.T) {
	yaml := "username: root\n" +
		"password: AbcdAbcd\n" +
		"secret: sk-2JuA6Vw5NC5kGVJCr9cALsWcU9DojWSfciYLPBYRklRiJhp4JvieCeTFy675fODv\n" +
		"app_key: skJua2VwNCr9CAL\n" +
		"secret_key: abababababab\n" +
		"alipay_public_key: eaeaeaeaeaeaeaeae\n" +
		"alipay_private_key: fsfsfsfsfsfsfsfsfsf\n"
	body, err := json.Marshal(map[string]any{"content": yaml})
	if err != nil {
		t.Fatalf("marshal yaml: %v", err)
	}
	res := scanJSONObjectForTest(t, body, testRules(), testTokenRe, testRedact)
	var out map[string]any
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	content := out["content"].(string)
	// Sensitive values must be gone.
	for _, secret := range []string{"AbcdAbcd", "skJua2VwNCr9CAL", "abababababab", "fsfsfsfsfsfsfsfsfsf"} {
		if strings.Contains(content, secret) {
			t.Fatalf("secret %q not redacted: %q", secret, content)
		}
	}
	// Non-secrets must be preserved verbatim, keys included.
	if !strings.Contains(content, "username: root") {
		t.Fatalf("non-secret username line should be untouched: %q", content)
	}
	if !strings.Contains(content, "alipay_public_key: eaeaeaeaeaeaeaeae") {
		t.Fatalf("public key line should be untouched: %q", content)
	}
	// Keys of redacted lines must be preserved (only the value is a token).
	for _, prefix := range []string{"password: ", "app_key: ", "secret_key: ", "alipay_private_key: "} {
		if !strings.Contains(content, prefix) {
			t.Fatalf("key prefix %q should be preserved: %q", prefix, content)
		}
	}
}

func TestOverlappingValueRulesDoNotRetokenizeEmittedTokens(t *testing.T) {
	rules := compileRules(false, nil, nil, nil, []customValueRule{
		{Name: "secret", Regex: `SECRET`},
		{Name: "token", Regex: `<REDACTED_[0-9a-f]{16}>`},
	})
	res := scanJSONObjectForTest(t, []byte(`{"note":"SECRET"}`), rules, nil, testRedact)
	if len(res.Matches) != 1 || res.Matches[0].Rule != "secret" {
		t.Fatalf("generated token was matched by a later value rule: %+v", res.Matches)
	}
	var out map[string]any
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	if got := out["note"].(string); got != testRedact("SECRET") {
		t.Fatalf("secret was tokenized more than once: %q", got)
	}
}
