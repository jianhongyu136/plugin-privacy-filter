package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/sirupsen/logrus"
)

// callRegister invokes handleMethod for a lifecycle method with the given YAML config.
func callRegister(t *testing.T, method, yamlText string) registration {
	t.Helper()
	req := lifecycleRequest(t, yamlText)
	raw, err := handleMethod(method, req)
	if err != nil {
		t.Fatalf("handleMethod(%s) error: %v", method, err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("expected ok envelope, got error: %+v", env.Error)
	}
	var reg registration
	if err := json.Unmarshal(env.Result, &reg); err != nil {
		t.Fatalf("unmarshal registration: %v", err)
	}
	return reg
}

func TestRegisterReturnsCapabilitiesAndMetadata(t *testing.T) {
	reg := callRegister(t, pluginabi.MethodPluginRegister, "")
	if !reg.Capabilities.RequestInterceptor || !reg.Capabilities.ResponseInterceptor || !reg.Capabilities.StreamChunkInterceptor || !reg.Capabilities.StreamChunkInterceptorStateful {
		t.Fatalf("expected all interceptor capabilities true, got %+v", reg.Capabilities)
	}
	if len(reg.Metadata.Name) == 0 || len(reg.Metadata.Version) == 0 || len(reg.Metadata.Author) == 0 || len(reg.Metadata.GitHubRepository) == 0 {
		t.Fatalf("expected all metadata strings non-empty, got %+v", reg.Metadata)
	}
	if len(reg.Metadata.ConfigFields) == 0 {
		t.Fatalf("expected config fields declared")
	}
}

func TestReconfigureRebuildsRuntimeState(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginReconfigure, "token_label: MASKED\nvault_max_entries: 7\nvault_ttl_seconds: 120\n")
	_, label := activeRuleSet()
	if label != "MASKED" {
		t.Fatalf("expected active label MASKED, got %q", label)
	}
	if getSharedVault() == nil {
		t.Fatalf("expected vault to be initialized after reconfigure")
	}
}

func TestReconfigureInvalidRuleReturnsErrorEnvelope(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "token_label: STABLE\n")
	before := activeSnapshot()
	raw, err := handleMethod(pluginabi.MethodPluginReconfigure, lifecycleRequest(t, "token_label: BROKEN\ncustom_value_rules:\n  - name: invalid\n    regex: '['\n"))
	if err != nil {
		t.Fatalf("handleMethod returned Go error: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.OK || env.Error == nil || env.Error.Code != "invalid_config" {
		t.Fatalf("expected invalid_config envelope, got %+v", env)
	}
	if activeSnapshot() != before {
		t.Fatal("failed reconfigure replaced the active snapshot")
	}
}

func TestUnknownMethodReturnsErrorEnvelope(t *testing.T) {
	raw, err := handleMethod("does.not.exist", nil)
	if err != nil {
		t.Fatalf("handleMethod returned Go error, expected error envelope: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.OK {
		t.Fatalf("expected ok=false for unknown method")
	}
	if env.Error == nil || env.Error.Code != "unknown_method" {
		t.Fatalf("expected unknown_method error, got %+v", env.Error)
	}
}

func TestEndToEndTokenizeThenDetokenize(t *testing.T) {
	// Configure with defaults (builtin rules on, label REDACTED).
	callRegister(t, pluginabi.MethodPluginRegister, ``)

	secret := "sk-abcdefghij0123456789"
	// Use a real OpenAI chat body so the secret sits inside a scanned content
	// region; the source format drives content-scoped scanning.
	reqBody, _ := json.Marshal(map[string]any{
		"model": "gpt-4",
		"messages": []any{
			map[string]any{"role": "user", "content": "use " + secret + " now"},
		},
	})

	// request.intercept_before tokenizes.
	interceptReq, _ := json.Marshal(pluginapi.RequestInterceptRequest{
		SourceFormat: formatOpenAI,
		Body:         reqBody,
	})
	interceptRaw, err := handleMethod(pluginabi.MethodRequestInterceptBefore, interceptReq)
	if err != nil {
		t.Fatalf("intercept_before error: %v", err)
	}
	var interceptEnv envelope
	if err := json.Unmarshal(interceptRaw, &interceptEnv); err != nil {
		t.Fatalf("unmarshal intercept env: %v", err)
	}
	if !interceptEnv.OK {
		t.Fatalf("intercept_before not ok: %+v", interceptEnv.Error)
	}
	var interceptResp pluginapi.RequestInterceptResponse
	if err := json.Unmarshal(interceptEnv.Result, &interceptResp); err != nil {
		t.Fatalf("unmarshal intercept resp: %v", err)
	}
	if len(interceptResp.Body) == 0 {
		t.Fatalf("expected tokenized body, got empty (no replacement)")
	}
	if bytesContains(interceptResp.Body, []byte(secret)) {
		t.Fatalf("tokenized body still contains the secret")
	}

	// response.intercept_after restores the original. RequestBody carries the
	// tokenized request body so the response allowlist is scoped to this request.
	respReq, _ := json.Marshal(pluginapi.ResponseInterceptRequest{
		RequestBody: interceptResp.Body,
		Body:        interceptResp.Body,
	})
	respRaw, err := handleMethod(pluginabi.MethodResponseInterceptAfter, respReq)
	if err != nil {
		t.Fatalf("intercept_after error: %v", err)
	}
	var respEnv envelope
	if err := json.Unmarshal(respRaw, &respEnv); err != nil {
		t.Fatalf("unmarshal resp env: %v", err)
	}
	if !respEnv.OK {
		t.Fatalf("intercept_after not ok: %+v", respEnv.Error)
	}
	var respResp pluginapi.ResponseInterceptResponse
	if err := json.Unmarshal(respEnv.Result, &respResp); err != nil {
		t.Fatalf("unmarshal resp resp: %v", err)
	}
	if !bytesContains(respResp.Body, []byte(secret)) {
		t.Fatalf("restored body missing the original secret")
	}
}

func TestBlockModeRejectsWithRedactedContextWithoutVaultWrites(t *testing.T) {
	config := "mode: block\ntoken_label: BLOCKED\nvault_max_entries: 1\nbuiltin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: BLOCKSECRET[0-9]+\n"
	callRegister(t, pluginabi.MethodPluginRegister, config)
	st := activeSnapshot()
	existingToken := makeToken(st.label, "in-flight")
	st.vault.Put(existingToken, "in-flight")

	body := []byte(`{"messages":[{"role":"user","content":"prefix BLOCKSECRET123 suffix"}]}`)
	response := invokeRequestIntercept(t, pluginabi.MethodRequestInterceptBefore, formatOpenAI, body)
	if !response.Reject {
		t.Fatal("block mode forwarded a request containing a privacy match")
	}
	if len(response.Body) != 0 {
		t.Fatalf("block response unexpectedly returned a body: %s", response.Body)
	}
	if strings.Contains(response.RejectReason, "BLOCKSECRET123") {
		t.Fatalf("block reason leaked plaintext: %q", response.RejectReason)
	}
	if !strings.Contains(response.RejectReason, "marker (value) at messages[0].content") ||
		!strings.Contains(response.RejectReason, `: "<BLOCKED_`) {
		t.Fatalf("block reason lacks the first match and redacted token: %q", response.RejectReason)
	}
	if got, ok := st.vault.Get(existingToken); !ok || got != "in-flight" {
		t.Fatalf("block mode evicted existing mapping: got=%q ok=%v", got, ok)
	}
	if st.vault.Len() != 1 {
		t.Fatalf("block mode persisted rejected plaintext: vault size=%d", st.vault.Len())
	}
}

func TestBlockModeReasonIsBoundedAndSanitized(t *testing.T) {
	config := "mode: block\ntoken_label: BLOCKED\nbuiltin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: BLOCKSECRET[0-9]+\n"
	callRegister(t, pluginabi.MethodPluginRegister, config)
	long := strings.Repeat("x", 220) + " BLOCKSECRET999\nINJECT"
	arguments, err := json.Marshal(map[string]any{"RAW-SECRET-KEY\nFORGED": long})
	if err != nil {
		t.Fatalf("marshal arguments: %v", err)
	}
	body, err := json.Marshal(map[string]any{"messages": []any{map[string]any{
		"role": "assistant", "content": nil,
		"function_call": map[string]any{"name": "run", "arguments": string(arguments)},
	}}})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	response := invokeRequestIntercept(t, pluginabi.MethodRequestInterceptBefore, formatOpenAI, body)
	if !response.Reject {
		t.Fatal("block mode did not reject runtime argument match")
	}
	if strings.Contains(response.RejectReason, "RAW-SECRET-KEY") || strings.Contains(response.RejectReason, "BLOCKSECRET999") || strings.Contains(response.RejectReason, "\nINJECT") {
		t.Fatalf("block reason leaked or preserved control characters: %q", response.RejectReason)
	}
	if !strings.Contains(response.RejectReason, ".arguments.*") || !strings.Contains(response.RejectReason, "<BLOCKED_") {
		t.Fatalf("block reason lacks sanitized path/context: %q", response.RejectReason)
	}
	if len(response.RejectReason) > 512 {
		t.Fatalf("block reason is not bounded: %d bytes", len(response.RejectReason))
	}
}

func TestBlockRejectReasonUsesJSONStringContext(t *testing.T) {
	reason := blockRejectReason([]scanMatch{{
		Rule: "marker", RuleType: "value", Path: "messages[0].content",
		Context: "before\x00<BLOCKED_0000000000000000>after",
	}})
	if strings.Contains(reason, `\x00`) || !strings.Contains(reason, `\u0000`) {
		t.Fatalf("context is not JSON-quoted: %q", reason)
	}
	quoted := reason[strings.LastIndex(reason, ": ")+2:]
	var context string
	if err := json.Unmarshal([]byte(quoted), &context); err != nil {
		t.Fatalf("quoted context is not a JSON string: %v (%q)", err, quoted)
	}
	if context != "before\x00<BLOCKED_0000000000000000>after" {
		t.Fatalf("decoded context = %q", context)
	}
}

func TestReconfigureBetweenRequestStagesDoesNotDoubleTokenize(t *testing.T) {
	config := "token_label: OLD\nbuiltin_rules_enabled: false\ncustom_field_rules:\n  - name: password\n    keys: [password]\n"
	callRegister(t, pluginabi.MethodPluginRegister, config)
	body := []byte(`{"messages":[{"role":"assistant","content":null,"function_call":{"name":"login","arguments":"{\"password\":\"stage-secret\"}"}}]}`)

	before := invokeRequestIntercept(t, pluginabi.MethodRequestInterceptBefore, formatOpenAI, body)
	if before.Reject || len(before.Body) == 0 || !strings.Contains(string(before.Body), "<OLD_") {
		t.Fatalf("before stage did not emit OLD token: reject=%v body=%s", before.Reject, before.Body)
	}
	callRegister(t, pluginabi.MethodPluginReconfigure, strings.Replace(config, "token_label: OLD", "token_label: NEW", 1))

	after := invokeRequestIntercept(t, pluginabi.MethodRequestInterceptAfter, formatOpenAI, before.Body)
	finalRequest := before.Body
	if len(after.Body) > 0 {
		finalRequest = after.Body
	}
	if strings.Contains(string(finalRequest), "<NEW_") {
		t.Fatalf("after stage double-tokenized an OLD token: %s", finalRequest)
	}

	responseReq, _ := json.Marshal(pluginapi.ResponseInterceptRequest{RequestBody: finalRequest, Body: finalRequest})
	raw, err := handleMethod(pluginabi.MethodResponseInterceptAfter, responseReq)
	if err != nil {
		t.Fatalf("response intercept: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal response envelope: %v", err)
	}
	var response pluginapi.ResponseInterceptResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !strings.Contains(string(response.Body), "stage-secret") || strings.Contains(string(response.Body), "<OLD_") {
		t.Fatalf("response did not restore original in one pass: %s", response.Body)
	}
}

func invokeRequestIntercept(t *testing.T, method, format string, body []byte) pluginapi.RequestInterceptResponse {
	t.Helper()
	req, _ := json.Marshal(pluginapi.RequestInterceptRequest{SourceFormat: format, Body: body})
	raw, err := handleMethod(method, req)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal request envelope: %v", err)
	}
	var response pluginapi.RequestInterceptResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("unmarshal request response: %v", err)
	}
	return response
}

type scanLogCapture struct {
	entries []logrus.Fields
}

func (h *scanLogCapture) Levels() []logrus.Level { return logrus.AllLevels }

func (h *scanLogCapture) Fire(entry *logrus.Entry) error {
	fields := make(logrus.Fields, len(entry.Data))
	for key, value := range entry.Data {
		fields[key] = value
	}
	h.entries = append(h.entries, fields)
	return nil
}

func captureScanLogs(t *testing.T, matches []scanMatch) []logrus.Fields {
	t.Helper()
	logger := logrus.StandardLogger()
	previousOutput := logger.Out
	previousHooks := logger.ReplaceHooks(make(logrus.LevelHooks))
	hook := &scanLogCapture{}
	logger.AddHook(hook)
	logger.SetOutput(io.Discard)
	t.Cleanup(func() {
		logger.SetOutput(previousOutput)
		logger.ReplaceHooks(previousHooks)
	})
	logScanMatches("request", matches)
	return hook.entries
}

func TestLogScanMatchesAggregatesAndBoundsPaths(t *testing.T) {
	var matches []scanMatch
	for i := 0; i < 10; i++ {
		matches = append(matches, scanMatch{
			Rule: "shared", RuleType: "field",
			Path: fmt.Sprintf("$.messages[%d]", i), Context: "plaintext-marker",
		})
	}
	matches = append(matches, matches[0])
	matches = append(matches, scanMatch{Rule: "shared", RuleType: "value", Path: "$.prompt", Context: "plaintext-marker"})

	entries := captureScanLogs(t, matches)
	if len(entries) != 2 {
		t.Fatalf("log entries = %d, want 2: %#v", len(entries), entries)
	}
	if entries[0]["rule"] != "shared" || entries[0]["type"] != "field" || entries[0]["hits"] != 11 {
		t.Fatalf("field group = %#v", entries[0])
	}
	paths, ok := entries[0]["paths"].([]string)
	if !ok || len(paths) != 8 || paths[0] != "$.messages[0]" || paths[7] != "$.messages[7]" {
		t.Fatalf("field paths = %#v", entries[0]["paths"])
	}
	if entries[0]["omitted_paths"] != 2 {
		t.Fatalf("omitted_paths = %#v, want 2", entries[0]["omitted_paths"])
	}
	if entries[1]["type"] != "value" || entries[1]["hits"] != 1 {
		t.Fatalf("value group = %#v", entries[1])
	}
	if strings.Contains(fmt.Sprint(entries), "plaintext-marker") {
		t.Fatalf("logs retained scan context: %#v", entries)
	}
}

// bytesContains is a tiny helper local to the test.
func bytesContains(haystack, needle []byte) bool {
	return len(needle) == 0 || indexOfBytes(haystack, needle) >= 0
}

func indexOfBytes(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
