package main

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/sirupsen/logrus"
)

func TestInvalidArgumentsReadOnlyDetectionHonorsMode(t *testing.T) {
	logger := logrus.StandardLogger()
	previousOutput, previousFormatter, previousLevel := logger.Out, logger.Formatter, logger.GetLevel()
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.WarnLevel)
	t.Cleanup(func() {
		logger.SetOutput(previousOutput)
		logger.SetFormatter(previousFormatter)
		logger.SetLevel(previousLevel)
	})

	providers := []struct {
		name, format, kind, path string
	}{
		{"chat tools", formatOpenAI, "tool_calls", "messages[0].tool_calls[0].function.arguments"},
		{"chat legacy", formatOpenAI, "function_call", "messages[0].function_call.arguments"},
		{"responses function", formatOpenAIResponse, "function_call", "input[0].arguments"},
		{"responses mcp", formatOpenAIResponse, "mcp_call", "input[0].arguments"},
		{"responses mcp approval", formatOpenAIResponse, "mcp_approval_request", "input[0].arguments"},
	}
	arguments := []struct {
		name, value string
		match       bool
	}{
		{"incomplete", `{"password":"SKIPPEDSECRET"`, true},
		{"unescaped quote", `{"cmd":"echo "SKIPPEDSECRET""}`, true},
		{"trailing value", `{"password":"SKIPPEDSECRET"} {}`, true},
		{"plain text", "SKIPPEDSECRET", true},
		{"clean malformed", `{"cmd":"echo hello"`, false},
		{"empty", "", false},
		{"whitespace", " \t\n", false},
	}
	for _, provider := range providers {
		for _, argument := range arguments {
			for _, mode := range []string{modeFilter, modeBlock} {
				for _, content := range []string{"ordinary text", "OTHERSECRET"} {
					t.Run(provider.name+"/"+argument.name+"/"+mode+"/"+content, func(t *testing.T) {
						callRegister(t, pluginabi.MethodPluginRegister, "mode: "+mode+"\nbuiltin_rules_enabled: false\ncustom_field_rules:\n  - name: password\n    keys: [password]\ncustom_value_rules:\n  - name: argument_marker\n    regex: SKIPPEDSECRET\n  - name: content_marker\n    regex: OTHERSECRET\n")
						owner := map[string]any{"arguments": argument.value}
						message := map[string]any{"role": "user", "content": content}
						var body map[string]any
						if provider.format == formatOpenAI {
							call := map[string]any{"role": "assistant", "content": nil}
							if provider.kind == "tool_calls" {
								call["tool_calls"] = []any{map[string]any{"type": "function", "function": owner}}
							} else {
								call["function_call"] = owner
							}
							body = map[string]any{"messages": []any{call, message}}
						} else {
							owner["type"] = provider.kind
							body = map[string]any{"input": []any{owner, message}}
						}
						logs.Reset()
						resp := requestIntercept(t, provider.format, mustJSONMarshal(t, body))
						wantReject := mode == modeBlock && (argument.match || content == "OTHERSECRET")
						if resp.Reject != wantReject {
							t.Fatalf("reject=%v, want %v: %s", resp.Reject, wantReject, resp.RejectReason)
						}
						if wantReject {
							wantRule := "content_marker"
							if argument.match {
								wantRule = "argument_marker"
								if !strings.Contains(resp.RejectReason, provider.path) {
									t.Fatalf("read-only finding did not identify the arguments: %s", resp.RejectReason)
								}
							}
							if !strings.Contains(resp.RejectReason, wantRule) || strings.Contains(resp.RejectReason, "SECRET") {
								t.Fatalf("unexpected or unsanitized block reason: %s", resp.RejectReason)
							}
						}
						if content != "OTHERSECRET" || wantReject {
							if len(resp.Body) != 0 {
								t.Fatalf("unexpected rewritten body: %s", resp.Body)
							}
						} else {
							var out map[string]any
							if err := json.Unmarshal(resp.Body, &out); err != nil {
								t.Fatalf("rewritten body is not valid JSON: %v", err)
							}
							var gotArguments any
							if provider.format == formatOpenAI {
								call := out["messages"].([]any)[0].(map[string]any)
								if provider.kind == "tool_calls" {
									gotArguments = call["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)["arguments"]
								} else {
									gotArguments = call["function_call"].(map[string]any)["arguments"]
								}
							} else {
								gotArguments = out["input"].([]any)[0].(map[string]any)["arguments"]
							}
							if gotArguments != argument.value {
								t.Fatalf("read-only arguments changed: got %q, want %q", gotArguments, argument.value)
							}
							if strings.Contains(string(resp.Body), "OTHERSECRET") {
								t.Fatalf("content after the read-only arguments was not redacted: %s", resp.Body)
							}
						}

						entries := bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte{'\n'})
						if len(entries) != 1 {
							t.Fatalf("want one warning per intercept, got %d: %s", len(entries), logs.String())
						}
						var entry map[string]any
						if err := json.Unmarshal(entries[0], &entry); err != nil {
							t.Fatalf("missing or invalid warning log: %v; %s", err, logs.String())
						}
						if entry["level"] != "warning" || entry["stage"] != "request" || entry["source_format"] != provider.format || entry["path"] != provider.path {
							t.Fatalf("unexpected warning context: %v", entry)
						}
						if detail, ok := entry["error"].(string); !ok || !strings.HasPrefix(detail, "arguments ") {
							t.Fatalf("warning is missing the sanitized parse reason: %v", entry)
						}
						wantHits := float64(0)
						if argument.match {
							wantHits = 1
							if !strings.Contains(logs.String(), "argument_marker") {
								t.Fatalf("warning omitted the detected rule: %s", logs.String())
							}
						}
						if entry["scan_mode"] != "read_only" || entry["mode"] != mode || entry["matched_rules"] != wantHits {
							t.Fatalf("unexpected read-only detection diagnostic: %v", entry)
						}
						if strings.Contains(logs.String(), "SKIPPEDSECRET") || strings.Contains(logs.String(), "password") || strings.Contains(logs.String(), "OTHERSECRET") {
							t.Fatalf("warning leaked argument or message contents: %s", logs.String())
						}
					})
				}
			}
		}
	}
}

func TestInvalidArgumentsDetectionHasNoReplacementSideEffects(t *testing.T) {
	v := newVault(10, time.Hour)
	token := makeToken("REDACTED", "existing secret")
	v.Put(token, "existing secret")
	tokens := existingTokenMatcher{candidate: restoreTokenPattern(), vault: v}
	acceptSecret := func(value string) bool { return value == "FALLBACKSECRET" }
	tests := []struct {
		name, arguments, pattern, original string
		validate                           func(string) bool
		wantMatches                        int
	}{
		{"capture group", "prefix=FALLBACKSECRET", `prefix=(FALLBACKSECRET)`, "FALLBACKSECRET", nil, 1},
		{"optional capture", "FALLBACKSECRET", `(optional)?FALLBACKSECRET`, "FALLBACKSECRET", nil, 1},
		{"validator rejects", "value=bad", `value=(bad)`, "", acceptSecret, 0},
		{"validator finds later match", "value=bad value=FALLBACKSECRET", `value=(bad|FALLBACKSECRET)`, "FALLBACKSECRET", acceptSecret, 1},
		{"empty capture", "FALLBACKSECRET", `()FALLBACKSECRET`, "", nil, 0},
		{"existing token", token, `REDACTED`, "", nil, 0},
		{"forged token", "<REDACTED_0000000000000000>", `REDACTED`, "REDACTED", nil, 1},
		{"secret beside token", token + " FALLBACKSECRET", `(REDACTED|FALLBACKSECRET)`, "FALLBACKSECRET", nil, 1},
	}
	for _, tc := range tests {
		for _, block := range []bool{false, true} {
			mode := modeFilter
			if block {
				mode = modeBlock
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				rules := ruleSet{valueRules: []valueRule{{name: "marker", re: regexp.MustCompile(tc.pattern), validate: tc.validate}}}
				body := mustJSONMarshal(t, map[string]any{"input": []any{map[string]any{"type": "function_call", "arguments": tc.arguments}}})
				redact := func(string) string {
					t.Fatal("read-only detection called the token-writing redactor")
					return ""
				}
				var result scanResult
				var handled bool
				var scanErr *contentScanError
				if block {
					result, handled, scanErr = scanRequestContentForBlock(body, formatOpenAIResponse, rules, tokens, redact, true)
				} else {
					result, handled, scanErr = scanRequestContent(body, formatOpenAIResponse, rules, tokens, redact)
				}
				if !handled || scanErr != nil {
					t.Fatalf("read-only scan failed: handled=%v error=%v", handled, scanErr)
				}
				if len(result.Matches) != 0 || len(result.ReadOnlyMatches) != tc.wantMatches {
					t.Fatalf("unexpected scan findings: redactions=%v read-only=%v", result.Matches, result.ReadOnlyMatches)
				}
				if block && tc.wantMatches > 0 {
					if len(result.Body) != 0 || result.ReadOnlyMatches[0].Context != tc.original {
						t.Fatalf("block scan did not preserve opt-in context or stopped incorrectly: %+v", result)
					}
				} else if !bytes.Equal(result.Body, body) {
					t.Fatal("read-only scan changed the original request bytes")
				}
				if !block && tc.wantMatches > 0 && result.ReadOnlyMatches[0].Context != "[redacted]" {
					t.Fatal("filter detection retained plaintext context")
				}
				if v.Len() != 1 {
					t.Fatal("read-only detection changed vault size")
				}
			})
		}
	}
}

func TestInvalidArgumentsReadOnlyOverlappingRulesAndEarlyStop(t *testing.T) {
	body := []byte(`{"input":[{"type":"function_call","arguments":"FALLBACKSECRET"}]}`)
	for _, mode := range []string{modeFilter, modeBlock} {
		t.Run(mode, func(t *testing.T) {
			secondRuleChecks := 0
			rules := ruleSet{valueRules: []valueRule{
				{name: "first", re: regexp.MustCompile(`FALLBACKSECRET`)},
				{name: "second", re: regexp.MustCompile(`FALLBACKSECRET`), validate: func(string) bool {
					secondRuleChecks++
					return true
				}},
			}}
			redact := func(string) string {
				t.Fatal("read-only detection attempted replacement")
				return ""
			}
			result, handled, scanErr := scanRequestContentWithOptions(body, formatOpenAIResponse, rules, testTokenRe, redact, mode == modeBlock, false)
			if !handled || scanErr != nil {
				t.Fatalf("scan failed: handled=%v error=%v", handled, scanErr)
			}
			wantMatches, wantSecondChecks := 2, 1
			if mode == modeBlock {
				wantMatches, wantSecondChecks = 1, 0
			}
			if len(result.ReadOnlyMatches) != wantMatches || secondRuleChecks != wantSecondChecks || len(result.Matches) != 0 {
				t.Fatalf("unexpected read-only scan: matches=%v second checks=%d redactions=%v", result.ReadOnlyMatches, secondRuleChecks, result.Matches)
			}
		})
	}
}
