package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/sirupsen/logrus"
)

// requestIntercept runs handleRequestIntercept for the given source format and
// body and returns the decoded response.
func requestIntercept(t *testing.T, sourceFormat string, body []byte) requestInterceptResult {
	t.Helper()
	req, _ := json.Marshal(pluginapi.RequestInterceptRequest{
		SourceFormat: sourceFormat,
		Body:         body,
	})
	raw, err := handleMethod(pluginabi.MethodRequestInterceptBefore, req)
	if err != nil {
		t.Fatalf("intercept error: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("expected ok envelope, got error: %+v", env.Error)
	}
	var resp pluginapi.RequestInterceptResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return requestResult(t, resp)
}

func TestOpenAIContentRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	secret := "sk-abcdefghij0123456789"
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"use ` + secret + ` please"}]}`)
	resp := requestIntercept(t, formatOpenAI, body)
	if len(resp.Body) == 0 {
		t.Fatalf("expected redacted body, got empty")
	}
	if strings.Contains(string(resp.Body), secret) {
		t.Fatalf("secret leaked in redacted body: %s", resp.Body)
	}
	// The model field and message structure must survive.
	var out map[string]any
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		t.Fatalf("redacted body not valid JSON: %v", err)
	}
	if out["model"] != "gpt-4" {
		t.Fatalf("model field altered: %v", out["model"])
	}
}

func TestBlockScanStopsAfterFirstMatchWithoutRewriting(t *testing.T) {
	rules := compileRules(false, nil, nil, nil, []customValueRule{{
		Name:  "marker",
		Regex: `BLOCKSECRET[0-9]+`,
	}})
	body := []byte(`{"messages":[{"role":"user","content":"BLOCKSECRET1"},{"role":"user","content":"BLOCKSECRET2"}]}`)
	var redacted []string
	redact := func(original string) string {
		redacted = append(redacted, original)
		return testRedact(original)
	}

	result, handled, scanErr := scanRequestContentForBlock(body, formatOpenAI, rules, testTokenRe, redact, false)
	if !handled || scanErr != nil {
		t.Fatalf("block scan failed: handled=%v err=%v", handled, scanErr)
	}
	if len(redacted) != 1 || redacted[0] != "BLOCKSECRET1" {
		t.Fatalf("block scan did not stop after the first match: redacted=%q", redacted)
	}
	if len(result.Matches) != 1 || result.Matches[0].Rule != "marker" || result.Matches[0].Path != "messages[0].content" {
		t.Fatalf("unexpected block matches: %+v", result.Matches)
	}
	if result.Matches[0].Context != testRedact("BLOCKSECRET1") {
		t.Fatalf("block context = %q, want only the redacted token", result.Matches[0].Context)
	}
	if len(result.Body) != 0 {
		t.Fatalf("block scan unnecessarily rewrote the body: %s", result.Body)
	}
}

// TestToolSchemaNotCollapsed is the core Solution A guarantee: a tool/function
// JSON schema with a parameter named like a field rule (api_key) must NOT be
// collapsed into a token; only content regions are scanned.
func TestToolSchemaNotCollapsed(t *testing.T) {
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"login","parameters":{"type":"object","properties":{"api_key":{"type":"string","description":"the key"},"password":{"type":"string"}}}}}]}`)
	// Scan directly to confirm the tools subtree is untouched by content-only
	// scanning.
	scanned, handled, scanErr := scanRequestContent(body, formatOpenAI, testRules(), testTokenRe, testRedact)
	if !handled {
		t.Fatalf("expected handled=true for openai body")
	}
	if scanErr != nil {
		t.Fatalf("openai body scan failed at %s: %s", scanErr.Path, scanErr.Detail)
	}
	// No content secret, so scanning yields no matches and original bytes.
	if len(scanned.Matches) != 0 {
		t.Fatalf("expected no matches, got %v", scanned.Matches)
	}
	var out map[string]any
	if err := json.Unmarshal(scanned.Body, &out); err != nil {
		t.Fatalf("scanned body not valid JSON: %v", err)
	}
	tools, ok := out["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools array missing or malformed: %v", out["tools"])
	}
	fn := tools[0].(map[string]any)["function"].(map[string]any)
	params := fn["parameters"].(map[string]any)
	props := params["properties"].(map[string]any)
	// api_key and password must still be schema objects, not collapsed tokens.
	if _, ok := props["api_key"].(map[string]any); !ok {
		t.Fatalf("api_key schema was collapsed: %v", props["api_key"])
	}
	if _, ok := props["password"].(map[string]any); !ok {
		t.Fatalf("password schema was collapsed: %v", props["password"])
	}
}

func TestClaudeContentAndSystemRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	secret := "sk-ant-abcdefghij0123456789"
	body := []byte(`{"model":"claude-3","system":"key is ` + secret + `","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	resp := requestIntercept(t, formatClaude, body)
	if len(resp.Body) == 0 {
		t.Fatalf("expected redacted body")
	}
	if strings.Contains(string(resp.Body), secret) {
		t.Fatalf("secret leaked: %s", resp.Body)
	}
}

func TestGeminiPartsRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	secret := "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	body := []byte(`{"contents":[{"role":"user","parts":[{"text":"token ` + secret + `"}]}]}`)
	resp := requestIntercept(t, formatGemini, body)
	if len(resp.Body) == 0 {
		t.Fatalf("expected redacted body")
	}
	if strings.Contains(string(resp.Body), secret) {
		t.Fatalf("secret leaked: %s", resp.Body)
	}
}

func TestGeminiFunctionRuntimeDataRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	apiKey := "AIza" + strings.Repeat("A", 35)
	body, err := json.Marshal(map[string]any{
		"contents": []any{
			map[string]any{
				"role": "user",
				"parts": []any{
					map[string]any{"functionCall": map[string]any{
						"name": "login",
						"args": map[string]any{"password": "gemini-password-marker", "endpoint": apiKey},
					}},
					map[string]any{"functionResponse": map[string]any{
						"name":     "login",
						"response": map[string]any{"secret": "gemini-response-marker"},
					}},
					map[string]any{"inlineData": map[string]any{
						"mimeType": "application/octet-stream",
						"data":     apiKey,
					}},
				},
			},
		},
		"tools": []any{map[string]any{
			"functionDeclarations": []any{map[string]any{
				"name":        "login",
				"description": apiKey,
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{"password": map[string]any{"type": "string"}},
				},
			}},
		}},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	resp := requestIntercept(t, formatGemini, body)
	if resp.Reject {
		t.Fatalf("valid Gemini function data rejected: %s", resp.RejectReason)
	}
	if len(resp.Body) == 0 {
		t.Fatal("Gemini function runtime data was not redacted")
	}

	var out map[string]any
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		t.Fatalf("redacted body is invalid JSON: %v", err)
	}
	parts := out["contents"].([]any)[0].(map[string]any)["parts"].([]any)
	args := parts[0].(map[string]any)["functionCall"].(map[string]any)["args"].(map[string]any)
	if args["password"] == "gemini-password-marker" || args["endpoint"] == apiKey {
		t.Fatalf("functionCall.args still contains plaintext: %v", args)
	}
	response := parts[1].(map[string]any)["functionResponse"].(map[string]any)["response"].(map[string]any)
	if response["secret"] == "gemini-response-marker" {
		t.Fatalf("functionResponse.response still contains plaintext: %v", response)
	}
	inline := parts[2].(map[string]any)["inlineData"].(map[string]any)
	if inline["data"] != apiKey {
		t.Fatalf("inlineData.data was modified: %v", inline["data"])
	}
	declaration := out["tools"].([]any)[0].(map[string]any)["functionDeclarations"].([]any)[0].(map[string]any)
	if declaration["description"] != apiKey {
		t.Fatalf("tool declaration was modified: %v", declaration)
	}
}

func TestRecognizedFormatStructureValidation(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	tests := []struct {
		name   string
		format string
		body   string
	}{
		{name: "openai missing messages", format: formatOpenAI, body: `{"model":"gpt-4"}`},
		{name: "openai messages wrong type", format: formatOpenAI, body: `{"messages":{}}`},
		{name: "openai message wrong type", format: formatOpenAI, body: `{"messages":["secret-marker"]}`},
		{name: "openai content wrong type", format: formatOpenAI, body: `{"messages":[{"content":42}]}`},
		{name: "responses missing input", format: formatOpenAIResponse, body: `{"model":"gpt-4"}`},
		{name: "responses input wrong type", format: formatOpenAIResponse, body: `{"input":{}}`},
		{name: "responses instructions wrong type", format: formatOpenAIResponse, body: `{"input":"ok","instructions":42}`},
		{name: "claude missing messages", format: formatClaude, body: `{"model":"claude"}`},
		{name: "claude message wrong type", format: formatClaude, body: `{"messages":["secret-marker"]}`},
		{name: "claude content missing", format: formatClaude, body: `{"messages":[{"role":"user"}]}`},
		{name: "claude content wrong type", format: formatClaude, body: `{"messages":[{"content":42}]}`},
		{name: "gemini missing contents", format: formatGemini, body: `{"model":"gemini"}`},
		{name: "gemini content wrong type", format: formatGemini, body: `{"contents":["secret-marker"]}`},
		{name: "gemini parts missing", format: formatGemini, body: `{"contents":[{"role":"user"}]}`},
		{name: "gemini part wrong type", format: formatGemini, body: `{"contents":[{"parts":["secret-marker"]}]}`},
		{name: "gemini text wrong type", format: formatGemini, body: `{"contents":[{"parts":[{"text":42}]}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := requestIntercept(t, tt.format, []byte(tt.body))
			if !resp.Reject {
				t.Fatalf("malformed recognized body was forwarded: body=%s", tt.body)
			}
			if strings.Contains(resp.RejectReason, "secret-marker") {
				t.Fatalf("reject reason leaked request content: %q", resp.RejectReason)
			}
		})
	}
}

func TestOpenAIResponseInputRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	secret := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	body := []byte(`{"model":"gpt-4","input":"my token is ` + secret + `"}`)
	resp := requestIntercept(t, formatOpenAIResponse, body)
	if len(resp.Body) == 0 {
		t.Fatalf("expected redacted body")
	}
	if strings.Contains(string(resp.Body), secret) {
		t.Fatalf("secret leaked: %s", resp.Body)
	}
}

func TestImageVideoPromptRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	apiKey := "sk-" + strings.Repeat("I", 22)
	for _, format := range []string{formatOpenAIImage, formatOpenAIVideo} {
		t.Run(format, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"prompt": "draw " + apiKey,
				"image":  "data:image/png;base64,MEDIA-MARKER",
				"mask":   map[string]any{"image_url": "https://example.invalid/mask.png"},
				"n":      2,
			})
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			resp := requestIntercept(t, format, body)
			if resp.Reject {
				t.Fatalf("valid prompt rejected: %s", resp.RejectReason)
			}
			if len(resp.Body) == 0 {
				t.Fatal("prompt was not redacted")
			}
			var out map[string]any
			if err := json.Unmarshal(resp.Body, &out); err != nil {
				t.Fatalf("redacted body is invalid JSON: %v", err)
			}
			if strings.Contains(out["prompt"].(string), apiKey) {
				t.Fatal("prompt still contains the secret")
			}
			if out["image"] != "data:image/png;base64,MEDIA-MARKER" {
				t.Fatalf("image field changed: %v", out["image"])
			}
			mask := out["mask"].(map[string]any)
			if mask["image_url"] != "https://example.invalid/mask.png" || out["n"] != float64(2) {
				t.Fatalf("non-prompt fields changed: mask=%v n=%v", mask, out["n"])
			}
		})
	}
}

func TestImageVideoPromptValidation(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	for _, format := range []string{formatOpenAIImage, formatOpenAIVideo} {
		t.Run(format+"/missing", func(t *testing.T) {
			resp := requestIntercept(t, format, []byte(`{"model":"image-model","image":"MEDIA-MARKER"}`))
			if resp.Reject || len(resp.Body) != 0 {
				t.Fatalf("missing prompt must pass unchanged: reject=%v body=%s", resp.Reject, resp.Body)
			}
		})
		t.Run(format+"/non-string", func(t *testing.T) {
			resp := requestIntercept(t, format, []byte(`{"prompt":{"value":"PROMPT-SECRET-MARKER"}}`))
			if !resp.Reject {
				t.Fatal("non-string prompt must be rejected")
			}
			if strings.Contains(resp.RejectReason, "PROMPT-SECRET-MARKER") {
				t.Fatalf("reject reason leaked prompt content: %q", resp.RejectReason)
			}
		})
	}
}

// TestUnmappedFormatRejected: any text format that is not one of the mainstream
// four must fail closed with Reject.
func TestUnmappedFormatRejected(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	for _, format := range []string{"codex", "antigravity", "interactions", "gemini-interactions", ""} {
		body := []byte(`{"input":"hello"}`)
		resp := requestIntercept(t, format, body)
		if !resp.Reject {
			t.Fatalf("format %q must be rejected", format)
		}
		if resp.RejectReason == "" {
			t.Fatalf("format %q reject must carry a reason", format)
		}
	}
}

func TestRecognizedFormatRequiresExactlyOneJSONObject(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	tests := []struct {
		name   string
		format string
		body   string
	}{
		{name: "invalid JSON", format: formatOpenAI, body: `not json`},
		{name: "trailing delimiter", format: formatOpenAI, body: `{"messages":[]} ]`},
		{name: "second value", format: formatOpenAI, body: `{"messages":[]} {}`},
		{name: "top-level null", format: formatOpenAIImage, body: `null`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := requestIntercept(t, tt.format, []byte(tt.body))
			if !resp.Reject {
				t.Fatalf("body must be rejected: %s", tt.body)
			}
		})
	}
}

func TestRejectedRequestDoesNotMutateVault(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "vault_max_entries: 1\nbuiltin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: NEWSECRET\n")
	v := getSharedVault()
	oldToken := makeToken("REDACTED", "existing-in-flight-secret")
	v.Put(oldToken, "existing-in-flight-secret")

	resp := requestIntercept(t, formatOpenAI, []byte(`{"messages":[{"content":"NEWSECRET"},{"content":42}]}`))
	if !resp.Reject {
		t.Fatal("structurally invalid request must be rejected")
	}
	if got, ok := v.Get(oldToken); !ok || got != "existing-in-flight-secret" {
		t.Fatalf("rejected request evicted the in-flight mapping: got=%q ok=%v", got, ok)
	}
	newToken := makeToken("REDACTED", "NEWSECRET")
	if got, ok := v.Get(newToken); ok {
		t.Fatalf("rejected request retained plaintext in vault: %q", got)
	}
}

func TestOpenAIToolCallArgumentsRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	apiKey := "sk-" + strings.Repeat("A", 22)
	arguments, err := json.Marshal(map[string]any{
		"password": "tool-password-marker",
		"endpoint": apiKey,
	})
	if err != nil {
		t.Fatalf("marshal arguments: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"model": "gpt-4",
		"messages": []any{
			map[string]any{
				"role":    "assistant",
				"content": nil,
				"tool_calls": []any{
					map[string]any{
						"type": "function",
						"function": map[string]any{
							"name":      "login",
							"arguments": string(arguments),
						},
					},
				},
			},
		},
		"tools": []any{
			map[string]any{
				"type": "function",
				"function": map[string]any{
					"name": "login",
					"parameters": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"password": map[string]any{"type": "string"},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	resp := requestIntercept(t, formatOpenAI, body)
	if resp.Reject {
		t.Fatalf("valid tool arguments rejected: %s", resp.RejectReason)
	}
	if len(resp.Body) == 0 {
		t.Fatal("tool arguments were not redacted")
	}

	var out map[string]any
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		t.Fatalf("redacted body is invalid JSON: %v", err)
	}
	message := out["messages"].([]any)[0].(map[string]any)
	toolCall := message["tool_calls"].([]any)[0].(map[string]any)
	function := toolCall["function"].(map[string]any)
	var gotArguments map[string]any
	if err := json.Unmarshal([]byte(function["arguments"].(string)), &gotArguments); err != nil {
		t.Fatalf("redacted arguments are invalid JSON: %v", err)
	}
	if gotArguments["password"] == "tool-password-marker" || gotArguments["endpoint"] == apiKey {
		t.Fatalf("tool arguments still contain unredacted values")
	}
	if !testTokenRe.MatchString(gotArguments["password"].(string)) || !testTokenRe.MatchString(gotArguments["endpoint"].(string)) {
		t.Fatalf("tool argument values are not tokens: password=%q endpoint=%q", gotArguments["password"], gotArguments["endpoint"])
	}

	tools := out["tools"].([]any)
	parameters := tools[0].(map[string]any)["function"].(map[string]any)["parameters"].(map[string]any)
	properties := parameters["properties"].(map[string]any)
	if _, ok := properties["password"].(map[string]any); !ok {
		t.Fatalf("tool schema password property was modified: %v", properties["password"])
	}
}

func TestOpenAIToolCallArgumentsValidation(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	tests := []struct {
		name      string
		arguments any
		reject    bool
	}{
		{name: "empty", arguments: "", reject: false},
		{name: "whitespace", arguments: " \t\n", reject: false},
		{name: "valid", arguments: `{}`, reject: false},
		{name: "malformed", arguments: `{"password":"argument-secret-marker"`, reject: true},
		{name: "trailing value", arguments: `{} {}`, reject: true},
		{name: "non-string", arguments: map[string]any{"password": "argument-secret-marker"}, reject: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"model": "gpt-4",
				"messages": []any{
					map[string]any{
						"role":    "assistant",
						"content": nil,
						"tool_calls": []any{
							map[string]any{
								"type": "function",
								"function": map[string]any{
									"name":      "login",
									"arguments": tt.arguments,
								},
							},
						},
					},
				},
			})
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			resp := requestIntercept(t, formatOpenAI, body)
			if resp.Reject != tt.reject {
				t.Fatalf("Reject = %v, want %v (reason=%q)", resp.Reject, tt.reject, resp.RejectReason)
			}
			if strings.Contains(resp.RejectReason, "argument-secret-marker") {
				t.Fatalf("reject reason leaked argument content: %q", resp.RejectReason)
			}
		})
	}
}

func TestOpenAIToolCallsNullAllowed(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	body := []byte(`{"model":"gpt-4","messages":[{"role":"assistant","content":null,"tool_calls":null}]}`)
	resp := requestIntercept(t, formatOpenAI, body)
	if resp.Reject {
		t.Fatalf("null tool_calls rejected: %s", resp.RejectReason)
	}
}

func TestOpenAILegacyFunctionCallArgumentsRedactedAndValidated(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_field_rules:\n  - name: password\n    keys: [password]\n")
	tests := []struct {
		name      string
		arguments any
		reject    bool
	}{
		{name: "valid", arguments: `{"password":"legacy-secret"}`, reject: false},
		{name: "malformed", arguments: `{"password":"legacy-secret"`, reject: true},
		{name: "non-string", arguments: map[string]any{"password": "legacy-secret"}, reject: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"messages": []any{map[string]any{
					"role":    "assistant",
					"content": nil,
					"function_call": map[string]any{
						"name":      "login",
						"arguments": tt.arguments,
					},
				}},
			})
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			resp := requestIntercept(t, formatOpenAI, body)
			if resp.Reject != tt.reject {
				t.Fatalf("Reject = %v, want %v (reason=%q)", resp.Reject, tt.reject, resp.RejectReason)
			}
			if strings.Contains(resp.RejectReason, "legacy-secret") {
				t.Fatalf("reject reason leaked arguments: %q", resp.RejectReason)
			}
			if tt.reject {
				return
			}
			if len(resp.Body) == 0 || strings.Contains(string(resp.Body), "legacy-secret") {
				t.Fatalf("legacy function arguments were not redacted: %s", resp.Body)
			}
		})
	}
}

func TestRuntimeObjectKeysDoNotAppearInLogs(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: KEYVALUESECRET\n")
	arguments, err := json.Marshal(map[string]any{"SECRET-KEY-NAME\nINJECT": "KEYVALUESECRET"})
	if err != nil {
		t.Fatalf("marshal arguments: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"messages": []any{map[string]any{
			"content": nil,
			"tool_calls": []any{map[string]any{
				"function": map[string]any{"arguments": string(arguments)},
			}},
		}},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	logger := logrus.StandardLogger()
	previousOutput := logger.Out
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	t.Cleanup(func() { logger.SetOutput(previousOutput) })

	resp := requestIntercept(t, formatOpenAI, body)
	if resp.Reject || len(resp.Body) == 0 {
		t.Fatalf("valid runtime object was not redacted: reject=%v reason=%q", resp.Reject, resp.RejectReason)
	}
	for _, forbidden := range []string{"SECRET-KEY-NAME", "INJECT", "KEYVALUESECRET"} {
		if strings.Contains(logs.String(), forbidden) {
			t.Fatalf("logs contain request-controlled content %q: %s", forbidden, logs.String())
		}
	}
	if !strings.Contains(logs.String(), ".*") {
		t.Fatalf("logs should retain a sanitized dynamic path: %s", logs.String())
	}
}

func TestProviderContentVisitorsExcludeMedia(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: '(TEXTSECRET|MEDIASECRET)'\n")
	tests := []struct {
		name       string
		format     string
		body       map[string]any
		mediaValue func(map[string]any) string
	}{
		{
			name:   "openai chat",
			format: formatOpenAI,
			body: map[string]any{"messages": []any{map[string]any{"content": []any{
				map[string]any{"type": "text", "text": "TEXTSECRET"},
				map[string]any{"type": "image_url", "image_url": map[string]any{"url": "https://example.invalid/MEDIASECRET", "detail": "MEDIASECRET"}},
			}}}},
			mediaValue: func(doc map[string]any) string {
				parts := doc["messages"].([]any)[0].(map[string]any)["content"].([]any)
				return parts[1].(map[string]any)["image_url"].(map[string]any)["url"].(string)
			},
		},
		{
			name:   "responses",
			format: formatOpenAIResponse,
			body: map[string]any{"input": []any{
				map[string]any{"type": "input_text", "text": "TEXTSECRET"},
				map[string]any{"type": "input_image", "image_url": "https://example.invalid/MEDIASECRET"},
			}},
			mediaValue: func(doc map[string]any) string {
				return doc["input"].([]any)[1].(map[string]any)["image_url"].(string)
			},
		},
		{
			name:   "claude",
			format: formatClaude,
			body: map[string]any{"messages": []any{map[string]any{"content": []any{
				map[string]any{"type": "text", "text": "TEXTSECRET"},
				map[string]any{"type": "image", "source": map[string]any{"type": "base64", "media_type": "MEDIASECRET", "data": "MEDIASECRET"}},
			}}}},
			mediaValue: func(doc map[string]any) string {
				parts := doc["messages"].([]any)[0].(map[string]any)["content"].([]any)
				return parts[1].(map[string]any)["source"].(map[string]any)["data"].(string)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			resp := requestIntercept(t, tt.format, body)
			if resp.Reject || len(resp.Body) == 0 {
				t.Fatalf("valid multimodal body was not redacted: reject=%v reason=%q", resp.Reject, resp.RejectReason)
			}
			if strings.Contains(string(resp.Body), "TEXTSECRET") {
				t.Fatalf("text field was not redacted: %s", resp.Body)
			}
			var out map[string]any
			if err := json.Unmarshal(resp.Body, &out); err != nil {
				t.Fatalf("redacted body is invalid JSON: %v", err)
			}
			if got := tt.mediaValue(out); !strings.Contains(got, "MEDIASECRET") {
				t.Fatalf("media field was modified: %q", got)
			}
		})
	}
}

func TestProviderRuntimeToolDataRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_field_rules:\n  - name: password\n    keys: [password]\n")
	tests := []struct {
		name   string
		format string
		body   map[string]any
	}{
		{
			name:   "responses function call",
			format: formatOpenAIResponse,
			body: map[string]any{"input": []any{map[string]any{
				"type": "function_call", "arguments": `{"password":"responses-secret"}`,
			}}},
		},
		{
			name:   "claude tool use",
			format: formatClaude,
			body: map[string]any{"messages": []any{map[string]any{"content": []any{map[string]any{
				"type": "tool_use", "input": map[string]any{"password": "claude-secret"},
			}}}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			resp := requestIntercept(t, tt.format, body)
			if resp.Reject || len(resp.Body) == 0 {
				t.Fatalf("runtime tool data was not redacted: reject=%v reason=%q", resp.Reject, resp.RejectReason)
			}
			if strings.Contains(string(resp.Body), "responses-secret") || strings.Contains(string(resp.Body), "claude-secret") {
				t.Fatalf("runtime tool data leaked: %s", resp.Body)
			}
		})
	}
}

func TestResponsesKnownInputItemsAcceptedAndTextRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: '(TEXTSECRET|OPAQUESECRET)'\n")
	body, err := json.Marshal(map[string]any{"instructions": nil, "input": []any{
		map[string]any{"role": "user", "content": "TEXTSECRET"},
		map[string]any{"type": "reasoning", "summary": []any{map[string]any{"type": "summary_text", "text": "TEXTSECRET"}}, "content": []any{map[string]any{"type": "reasoning_text", "text": "TEXTSECRET"}}, "encrypted_content": "OPAQUESECRET"},
		map[string]any{"type": "custom_tool_call", "name": "apply_patch", "input": "TEXTSECRET"},
		map[string]any{"type": "custom_tool_call_output", "output": "TEXTSECRET"},
		map[string]any{"type": "computer_call_output", "output": map[string]any{"type": "computer_screenshot", "image_url": "OPAQUESECRET"}},
		map[string]any{"id": "msg-reference"},
		map[string]any{"type": "computer_call", "action": map[string]any{"type": "type", "text": "TEXTSECRET"}},
		map[string]any{"type": "local_shell_call", "action": map[string]any{"type": "exec", "command": []any{"echo", "TEXTSECRET"}, "env": map[string]any{"TOKEN": "TEXTSECRET"}}},
		map[string]any{"type": "local_shell_call_output", "output": `"TEXTSECRET"`},
		map[string]any{"type": "compaction_trigger"},
	}})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	resp := requestIntercept(t, formatOpenAIResponse, body)
	if resp.Reject || len(resp.Body) == 0 {
		t.Fatalf("valid Responses input rejected or unchanged: reject=%v reason=%q", resp.Reject, resp.RejectReason)
	}
	var out map[string]any
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		t.Fatalf("redacted body is invalid JSON: %v", err)
	}
	items := out["input"].([]any)
	if strings.Contains(string(resp.Body), "TEXTSECRET") {
		t.Fatalf("visible Responses text was not redacted: %s", resp.Body)
	}
	reasoning := items[1].(map[string]any)
	if reasoning["encrypted_content"] != "OPAQUESECRET" {
		t.Fatalf("encrypted reasoning was modified: %v", reasoning["encrypted_content"])
	}
	computer := items[4].(map[string]any)["output"].(map[string]any)
	if computer["image_url"] != "OPAQUESECRET" {
		t.Fatalf("computer screenshot was modified: %v", computer["image_url"])
	}
}

func TestResponsesTypedMessageRequiresContent(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	resp := requestIntercept(t, formatOpenAIResponse, []byte(`{"input":[{"type":"message","id":"msg-reference"}]}`))
	if !resp.Reject {
		t.Fatal("typed message without role/content must be rejected")
	}
}

func TestResponsesAgentMessageAcceptedAndTextRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: '(TEXTSECRET|OPAQUESECRET)'\n")
	body := []byte(`{"input":[{"type":"agent_message","id":"amsg_1","author":"/root","recipient":"/root/worker","content":[{"type":"input_text","text":"TEXTSECRET"},{"type":"encrypted_content","encrypted_content":"OPAQUESECRET"}],"internal_chat_message_metadata_passthrough":{"turn_id":"turn_1"}}]}`)

	resp := requestIntercept(t, formatOpenAIResponse, body)
	if resp.Reject || len(resp.Body) == 0 {
		t.Fatalf("valid agent_message rejected or unchanged: reject=%v reason=%q", resp.Reject, resp.RejectReason)
	}
	if strings.Contains(string(resp.Body), "TEXTSECRET") {
		t.Fatalf("agent message text was not redacted: %s", resp.Body)
	}
	if !strings.Contains(string(resp.Body), "OPAQUESECRET") || !strings.Contains(string(resp.Body), "turn_1") {
		t.Fatalf("opaque agent message data was modified: %s", resp.Body)
	}
}

func TestResponsesDiscriminatedInputsFailClosed(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	tests := []string{
		`{"input":[{"id":"ref","payload":"unscanned"}]}`,
		`{"input":[{"type":"computer_call","action":{"type":"paste","text":"unscanned"}}]}`,
		`{"input":[{"type":"local_shell_call","action":{"type":"future","command":"unscanned"}}]}`,
	}
	for _, body := range tests {
		resp := requestIntercept(t, formatOpenAIResponse, []byte(body))
		if !resp.Reject {
			t.Fatalf("malformed Responses union was accepted: %s", body)
		}
		if strings.Contains(resp.RejectReason, "unscanned") {
			t.Fatalf("reject reason leaked input content: %q", resp.RejectReason)
		}
	}
}

func TestResponsesCurrentRuntimeItemsRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_field_rules:\n  - name: password\n    keys: [password]\ncustom_value_rules:\n  - name: marker\n    regex: '(TEXTSECRET|OPAQUESECRET)'\n")
	items := []any{
		map[string]any{"type": "local_shell_call_output", "output": `{"password":"shell-secret"}`},
		map[string]any{"type": "computer_call", "actions": []any{map[string]any{"type": "type", "text": "TEXTSECRET"}}},
		map[string]any{"type": "shell_call", "action": map[string]any{"commands": []any{"echo TEXTSECRET"}}},
		map[string]any{"type": "shell_call_output", "output": []any{map[string]any{"stdout": "TEXTSECRET", "stderr": "TEXTSECRET", "outcome": map[string]any{"type": "exit", "exit_code": 0}}}},
		map[string]any{"type": "apply_patch_call", "operation": map[string]any{"type": "update_file", "path": "TEXTSECRET", "diff": "TEXTSECRET"}},
		map[string]any{"type": "apply_patch_call_output", "output": "TEXTSECRET"},
		map[string]any{"type": "mcp_list_tools", "error": "TEXTSECRET", "tools": []any{map[string]any{"name": "opaque", "description": "OPAQUESECRET", "input_schema": map[string]any{"password": "OPAQUESECRET"}}}},
		map[string]any{"type": "mcp_approval_request", "arguments": `{"password":"mcp-secret"}`},
		map[string]any{"type": "mcp_approval_response", "reason": "TEXTSECRET"},
		map[string]any{"type": "mcp_call", "arguments": `{"password":"mcp-call-secret"}`, "error": "TEXTSECRET", "output": "TEXTSECRET"},
		map[string]any{"type": "program", "code": "TEXTSECRET", "fingerprint": "OPAQUESECRET"},
		map[string]any{"type": "program_output", "result": "TEXTSECRET"},
		map[string]any{"type": "code_interpreter_call", "code": "TEXTSECRET", "outputs": []any{map[string]any{"type": "logs", "logs": "TEXTSECRET"}, map[string]any{"type": "image", "url": "OPAQUESECRET"}}},
		map[string]any{"type": "web_search_call", "action": map[string]any{"type": "search", "queries": []any{"TEXTSECRET"}, "sources": []any{map[string]any{"type": "url", "url": "OPAQUESECRET"}}}},
		map[string]any{"type": "file_search_call", "queries": []any{"TEXTSECRET"}, "results": []any{map[string]any{"file_id": "OPAQUESECRET", "text": "TEXTSECRET"}}},
		map[string]any{"type": "tool_search_call", "arguments": map[string]any{"password": "tool-search-secret"}},
		map[string]any{"type": "tool_search_output", "tools": []any{map[string]any{"type": "function", "parameters": map[string]any{"password": "OPAQUESECRET"}}}},
		map[string]any{"type": "additional_tools", "tools": []any{map[string]any{"type": "function", "parameters": map[string]any{"password": "OPAQUESECRET"}}}},
	}
	body, err := json.Marshal(map[string]any{"input": items})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	resp := requestIntercept(t, formatOpenAIResponse, body)
	if resp.Reject || len(resp.Body) == 0 {
		t.Fatalf("valid current Responses items rejected or unchanged: reject=%v reason=%q", resp.Reject, resp.RejectReason)
	}
	if strings.Contains(string(resp.Body), "TEXTSECRET") || strings.Contains(string(resp.Body), "shell-secret") || strings.Contains(string(resp.Body), "mcp-secret") || strings.Contains(string(resp.Body), "mcp-call-secret") || strings.Contains(string(resp.Body), "tool-search-secret") {
		t.Fatalf("Responses runtime text was not redacted: %s", resp.Body)
	}
	if !strings.Contains(string(resp.Body), "OPAQUESECRET") {
		t.Fatalf("opaque Responses metadata was unexpectedly modified: %s", resp.Body)
	}
}

func TestResponsesAdditionalToolsRoleAccepted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: '(TEXTSECRET|TOOLSCHEMASECRET)'\n")
	body := []byte(`{"input":[{"type":"additional_tools","role":"developer","tools":[{"type":"custom","name":"exec","description":"TOOLSCHEMASECRET"}]},{"type":"message","role":"user","content":[{"type":"input_text","text":"TEXTSECRET"}]}]}`)

	resp := requestIntercept(t, formatOpenAIResponse, body)
	if resp.Reject || len(resp.Body) == 0 {
		t.Fatalf("additional_tools with role rejected or unchanged: reject=%v reason=%q", resp.Reject, resp.RejectReason)
	}
	if strings.Contains(string(resp.Body), "TEXTSECRET") {
		t.Fatalf("message text was not redacted: %s", resp.Body)
	}
	if !strings.Contains(string(resp.Body), `"role":"developer"`) || !strings.Contains(string(resp.Body), "TOOLSCHEMASECRET") {
		t.Fatalf("additional_tools metadata was modified: %s", resp.Body)
	}
}

func TestResponsesAdditionalToolsRoleMustBeString(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	for _, role := range []string{`{"secret":"MUST-NOT-PASS"}`, "null", `""`, `"   "`} {
		body := []byte(`{"input":[{"type":"additional_tools","role":` + role + `,"tools":[]}]}`)
		resp := requestIntercept(t, formatOpenAIResponse, body)
		if !resp.Reject {
			t.Fatalf("additional_tools with invalid role %s was accepted", role)
		}
		if strings.Contains(resp.RejectReason, "MUST-NOT-PASS") {
			t.Fatalf("reject reason leaked role content: %q", resp.RejectReason)
		}
	}
}

func TestResponsesToolSearchOutputDoesNotAcceptAdditionalToolsRole(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	body := []byte(`{"input":[{"type":"tool_search_output","role":"developer","tools":[]}]}`)

	if resp := requestIntercept(t, formatOpenAIResponse, body); !resp.Reject {
		t.Fatal("tool_search_output with additional_tools-only role was accepted")
	}
}

func TestResponsesCurrentRuntimeUnionsFailClosed(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	tests := []string{
		`{"input":[{"type":"computer_call","actions":[{"type":"future","payload":"unscanned"}]}]}`,
		`{"input":[{"type":"shell_call","action":{"commands":[42]}}]}`,
		`{"input":[{"type":"apply_patch_call","operation":{"type":"future","diff":"unscanned"}}]}`,
		`{"input":[{"type":"shell_call_output","output":[{"stdout":"ok","stderr":"","outcome":{"type":"future"}}]}]}`,
	}
	for _, body := range tests {
		resp := requestIntercept(t, formatOpenAIResponse, []byte(body))
		if !resp.Reject {
			t.Fatalf("invalid current Responses union was accepted: %s", body)
		}
		if strings.Contains(resp.RejectReason, "unscanned") {
			t.Fatalf("reject reason leaked runtime content: %q", resp.RejectReason)
		}
	}
}

func TestOpenAIToolCallRequiresFunctionArguments(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	tests := []string{
		`{"messages":[{"role":"assistant","content":null,"tool_calls":[{"type":"function"}]}]}`,
		`{"messages":[{"role":"assistant","content":null,"tool_calls":[{"type":"function","function":{"name":"run"}}]}]}`,
	}
	for _, body := range tests {
		if resp := requestIntercept(t, formatOpenAI, []byte(body)); !resp.Reject {
			t.Fatalf("tool call without required runtime arguments was accepted: %s", body)
		}
	}
}

func TestOpenAIMessageMetadataAndCustomToolCallRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: TEXTSECRET\n")
	body, err := json.Marshal(map[string]any{"messages": []any{map[string]any{
		"role":              "assistant",
		"content":           nil,
		"refusal":           "TEXTSECRET",
		"reasoning_content": "TEXTSECRET",
		"tool_calls": []any{map[string]any{
			"type":   "custom",
			"custom": map[string]any{"name": "runner", "input": "TEXTSECRET"},
		}},
	}}})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	resp := requestIntercept(t, formatOpenAI, body)
	if resp.Reject || len(resp.Body) == 0 {
		t.Fatalf("valid OpenAI message metadata/custom call rejected or unchanged: reject=%v reason=%q", resp.Reject, resp.RejectReason)
	}
	if strings.Contains(string(resp.Body), "TEXTSECRET") {
		t.Fatalf("OpenAI runtime text was not redacted: %s", resp.Body)
	}
}

func TestOpenAIToolCallDiscriminatorFailsClosed(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	tests := []string{
		`{"messages":[{"role":"assistant","content":null,"tool_calls":[{"type":"custom","custom":{"name":"runner"}}]}]}`,
		`{"messages":[{"role":"assistant","content":null,"tool_calls":[{"type":"future","payload":"unscanned"}]}]}`,
	}
	for _, body := range tests {
		resp := requestIntercept(t, formatOpenAI, []byte(body))
		if !resp.Reject {
			t.Fatalf("invalid tool call union was accepted: %s", body)
		}
		if strings.Contains(resp.RejectReason, "unscanned") {
			t.Fatalf("reject reason leaked tool call content: %q", resp.RejectReason)
		}
	}
}

func TestClaudeKnownResultBlocksAcceptedAndTextRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: '(TEXTSECRET|OPAQUESECRET)'\n")
	body, err := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": []any{
		map[string]any{"type": "tool_result", "tool_use_id": "tool-1"},
		map[string]any{"type": "tool_reference", "tool_name": "OPAQUESECRET"},
		map[string]any{"type": "web_search_tool_result", "tool_use_id": "search-1", "content": []any{
			map[string]any{"type": "web_search_result", "title": "TEXTSECRET", "url": "https://example.invalid/OPAQUESECRET", "encrypted_content": "OPAQUESECRET"},
		}},
		map[string]any{"type": "search_result", "content": []any{map[string]any{"type": "text", "text": "TEXTSECRET"}}},
		map[string]any{"type": "mcp_tool_result", "tool_use_id": "mcp-1", "content": []any{map[string]any{"type": "text", "text": "TEXTSECRET"}}},
		map[string]any{"type": "tool_result", "tool_use_id": "tool-2", "content": []any{map[string]any{"type": "tool_reference", "tool_name": "OPAQUESECRET"}}},
	}}}})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	resp := requestIntercept(t, formatClaude, body)
	if resp.Reject || len(resp.Body) == 0 {
		t.Fatalf("valid Claude result blocks rejected or unchanged: reject=%v reason=%q", resp.Reject, resp.RejectReason)
	}
	if strings.Contains(string(resp.Body), "TEXTSECRET") {
		t.Fatalf("visible Claude result text was not redacted: %s", resp.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		t.Fatalf("redacted body is invalid JSON: %v", err)
	}
	blocks := out["messages"].([]any)[0].(map[string]any)["content"].([]any)
	if blocks[1].(map[string]any)["tool_name"] != "OPAQUESECRET" {
		t.Fatalf("tool reference changed: %v", blocks[1])
	}
	result := blocks[2].(map[string]any)["content"].([]any)[0].(map[string]any)
	if result["url"] != "https://example.invalid/OPAQUESECRET" || result["encrypted_content"] != "OPAQUESECRET" {
		t.Fatalf("opaque search result fields changed: %v", result)
	}
}

func TestClaudeObjectToolResultsAcceptedAndTextRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: '(TEXTSECRET|OPAQUESECRET)'\n")
	body, err := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": []any{
		map[string]any{"type": "web_fetch_tool_result", "tool_use_id": "fetch-1", "content": map[string]any{
			"type": "web_fetch_result", "url": "https://example.invalid/OPAQUESECRET", "content": map[string]any{
				"type": "document", "title": "TEXTSECRET", "source": map[string]any{"type": "text", "media_type": "text/plain", "data": "TEXTSECRET"},
			},
		}},
		map[string]any{"type": "code_execution_tool_result", "tool_use_id": "code-1", "content": map[string]any{
			"type": "code_execution_result", "stdout": "TEXTSECRET", "stderr": "TEXTSECRET", "return_code": 0,
			"content": []any{map[string]any{"type": "code_execution_output", "file_id": "OPAQUESECRET"}},
		}},
		map[string]any{"type": "code_execution_tool_result", "tool_use_id": "code-2", "content": map[string]any{
			"type": "encrypted_code_execution_result", "encrypted_stdout": "OPAQUESECRET", "stderr": "TEXTSECRET", "return_code": 1, "content": []any{},
		}},
		map[string]any{"type": "bash_code_execution_tool_result", "tool_use_id": "bash-1", "content": map[string]any{
			"type": "bash_code_execution_result", "stdout": "TEXTSECRET", "stderr": "TEXTSECRET", "return_code": 0, "content": []any{},
		}},
		map[string]any{"type": "text_editor_code_execution_tool_result", "tool_use_id": "edit-1", "content": map[string]any{
			"type": "text_editor_code_execution_view_result", "file_type": "text", "content": "TEXTSECRET",
		}},
		map[string]any{"type": "text_editor_code_execution_tool_result", "tool_use_id": "edit-2", "content": map[string]any{
			"type": "text_editor_code_execution_str_replace_result", "lines": []any{"TEXTSECRET"},
		}},
		map[string]any{"type": "text_editor_code_execution_tool_result", "tool_use_id": "edit-3", "content": map[string]any{
			"type": "text_editor_code_execution_tool_result_error", "error_code": "file_not_found", "error_message": "TEXTSECRET",
		}},
		map[string]any{"type": "web_search_tool_result", "tool_use_id": "search-1", "content": map[string]any{
			"type": "web_search_tool_result_error", "error_code": "unavailable",
		}},
	}}}})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	resp := requestIntercept(t, formatClaude, body)
	if resp.Reject || len(resp.Body) == 0 {
		t.Fatalf("valid Claude object results rejected or unchanged: reject=%v reason=%q", resp.Reject, resp.RejectReason)
	}
	if strings.Contains(string(resp.Body), "TEXTSECRET") {
		t.Fatalf("visible Claude object result text was not redacted: %s", resp.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		t.Fatalf("redacted body is invalid JSON: %v", err)
	}
	blocks := out["messages"].([]any)[0].(map[string]any)["content"].([]any)
	fetch := blocks[0].(map[string]any)["content"].(map[string]any)
	if fetch["url"] != "https://example.invalid/OPAQUESECRET" {
		t.Fatalf("web fetch URL changed: %v", fetch["url"])
	}
	code := blocks[1].(map[string]any)["content"].(map[string]any)
	if code["content"].([]any)[0].(map[string]any)["file_id"] != "OPAQUESECRET" {
		t.Fatalf("code output file id changed: %v", code["content"])
	}
	encrypted := blocks[2].(map[string]any)["content"].(map[string]any)
	if encrypted["encrypted_stdout"] != "OPAQUESECRET" {
		t.Fatalf("encrypted stdout changed: %v", encrypted["encrypted_stdout"])
	}
}

func TestClaudeDocumentsAndCurrentBlocksAcceptedAndTextRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: '(TEXTSECRET|OPAQUESECRET)'\n")
	blocks := []any{
		map[string]any{"type": "document", "title": "TEXTSECRET", "context": "TEXTSECRET", "source": map[string]any{"type": "text", "media_type": "text/plain", "data": "TEXTSECRET"}},
		map[string]any{"type": "document", "source": map[string]any{"type": "base64", "media_type": "application/pdf", "data": "OPAQUESECRET"}},
		map[string]any{"type": "tool_result", "tool_use_id": "tool-1", "content": []any{
			map[string]any{"type": "document", "source": map[string]any{"type": "content", "content": []any{
				map[string]any{"type": "text", "text": "TEXTSECRET"},
				map[string]any{"type": "image", "source": map[string]any{"type": "base64", "data": "OPAQUESECRET"}},
			}}},
		}},
		map[string]any{"type": "tool_search_tool_result", "tool_use_id": "search-1", "content": map[string]any{"type": "tool_search_tool_result_error", "error_code": "unavailable", "error_message": "TEXTSECRET"}},
		map[string]any{"type": "tool_search_tool_result", "tool_use_id": "search-2", "content": map[string]any{"type": "tool_search_tool_search_result", "tool_references": []any{map[string]any{"type": "tool_reference", "tool_name": "OPAQUESECRET"}}}},
		map[string]any{"type": "container_upload", "file_id": "OPAQUESECRET"},
		map[string]any{"type": "mid_conv_system", "content": []any{map[string]any{"type": "text", "text": "TEXTSECRET"}}},
	}
	body, err := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": blocks}}})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	resp := requestIntercept(t, formatClaude, body)
	if resp.Reject || len(resp.Body) == 0 {
		t.Fatalf("valid Claude blocks rejected or unchanged: reject=%v reason=%q", resp.Reject, resp.RejectReason)
	}
	if strings.Contains(string(resp.Body), "TEXTSECRET") {
		t.Fatalf("visible Claude text was not redacted: %s", resp.Body)
	}
	if !strings.Contains(string(resp.Body), "OPAQUESECRET") {
		t.Fatalf("opaque Claude data was unexpectedly changed: %s", resp.Body)
	}
}

func TestClaudeNestedOnlyAndUnknownResultKindsReject(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	tests := []string{
		`{"messages":[{"content":[{"type":"code_execution_result","stdout":"unscanned","stderr":""}]}]}`,
		`{"messages":[{"content":[{"type":"text_editor_code_execution_tool_result","tool_use_id":"x","content":{"type":"text_editor_code_execution_view_result","file_type":"future","content":"unscanned"}}]}]}`,
	}
	for _, body := range tests {
		resp := requestIntercept(t, formatClaude, []byte(body))
		if !resp.Reject {
			t.Fatalf("invalid Claude union was accepted: %s", body)
		}
		if strings.Contains(resp.RejectReason, "unscanned") {
			t.Fatalf("reject reason leaked content: %q", resp.RejectReason)
		}
	}
}

func TestGeminiPartUnionFailsClosed(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	invalid := []struct {
		name string
		body string
	}{
		{name: "unknown part", body: `{"contents":[{"parts":[{"futurePart":{"payload":"unscanned"}}]}]}`},
		{name: "unknown member", body: `{"contents":[{"parts":[{"text":"hello","unknown":"unscanned"}]}]}`},
		{name: "metadata only", body: `{"contents":[{"parts":[{"mediaResolution":{"level":"high"},"partMetadata":{}}]}]}`},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			resp := requestIntercept(t, formatGemini, []byte(tt.body))
			if !resp.Reject {
				t.Fatalf("invalid Gemini part structure was accepted: %s", tt.body)
			}
			if strings.Contains(resp.RejectReason, "unscanned") {
				t.Fatalf("reject reason leaked Gemini content: %q", resp.RejectReason)
			}
		})
	}
}

func TestGeminiCurrentToolPartsAcceptedAndRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_field_rules:\n  - name: password\n    keys: [password]\ncustom_value_rules:\n  - name: marker\n    regex: '(TEXTSECRET|OPAQUESECRET)'\n")
	body, err := json.Marshal(map[string]any{"contents": []any{map[string]any{"parts": []any{
		map[string]any{"toolCall": map[string]any{"id": "OPAQUESECRET", "toolType": "OPAQUESECRET", "args": map[string]any{"password": "tool-secret"}}, "mediaResolution": map[string]any{"level": "OPAQUESECRET"}, "partMetadata": map[string]any{"opaque": "OPAQUESECRET"}},
		map[string]any{"toolResponse": map[string]any{"id": "OPAQUESECRET", "toolType": "OPAQUESECRET", "response": map[string]any{"password": "response-secret"}}},
	}}}})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	resp := requestIntercept(t, formatGemini, body)
	if resp.Reject || len(resp.Body) == 0 {
		t.Fatalf("valid current Gemini tool parts rejected or unchanged: reject=%v reason=%q", resp.Reject, resp.RejectReason)
	}
	if strings.Contains(string(resp.Body), "tool-secret") || strings.Contains(string(resp.Body), "response-secret") {
		t.Fatalf("Gemini current runtime data was not redacted: %s", resp.Body)
	}
	if !strings.Contains(string(resp.Body), "OPAQUESECRET") {
		t.Fatalf("Gemini tool metadata was unexpectedly modified: %s", resp.Body)
	}
}

func TestRecognizedProviderObjectsRejectUnknownMembers(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	tests := []struct {
		name   string
		format string
		body   string
	}{
		{
			name:   "openai message",
			format: formatOpenAI,
			body:   `{"messages":[{"role":"user","content":"ok","future":{"password":"unscanned"}}]}`,
		},
		{
			name:   "responses item",
			format: formatOpenAIResponse,
			body:   `{"input":[{"type":"program","code":"ok","future":{"password":"unscanned"}}]}`,
		},
		{
			name:   "claude block",
			format: formatClaude,
			body:   `{"messages":[{"role":"user","content":[{"type":"text","text":"ok","future":{"password":"unscanned"}}]}]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := requestIntercept(t, tt.format, []byte(tt.body))
			if !resp.Reject {
				t.Fatalf("recognized object with unknown member was accepted: %s", tt.body)
			}
			if strings.Contains(resp.RejectReason, "unscanned") || strings.Contains(resp.RejectReason, "future") {
				t.Fatalf("reject reason leaked member name or content: %q", resp.RejectReason)
			}
		})
	}
}

func TestCurrentProviderRuntimeFieldsRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "builtin_rules_enabled: false\ncustom_value_rules:\n  - name: marker\n    regex: TEXTSECRET\n")
	tests := []struct {
		name   string
		format string
		body   map[string]any
	}{
		{
			name:   "responses safety and shell fields",
			format: formatOpenAIResponse,
			body: map[string]any{"input": []any{
				map[string]any{"type": "computer_call", "action": map[string]any{"type": "wait"}, "pending_safety_checks": []any{map[string]any{"id": "safe-id", "code": "safe-code", "message": "TEXTSECRET"}}},
				map[string]any{"type": "local_shell_call", "action": map[string]any{"type": "exec", "command": []any{"echo"}, "user": "TEXTSECRET", "working_directory": "TEXTSECRET"}},
			}},
		},
		{
			name:   "gemini partial arguments",
			format: formatGemini,
			body: map[string]any{"contents": []any{map[string]any{
				"parts": []any{map[string]any{"functionCall": map[string]any{
					"name": "run",
					"partialArgs": []any{map[string]any{
						"jsonPath": "$.value", "stringValue": "TEXTSECRET", "willContinue": false,
					}},
				}}},
			}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			resp := requestIntercept(t, tt.format, body)
			if resp.Reject || len(resp.Body) == 0 {
				t.Fatalf("valid runtime fields rejected or unchanged: reject=%v reason=%q", resp.Reject, resp.RejectReason)
			}
			if strings.Contains(string(resp.Body), "TEXTSECRET") {
				t.Fatalf("runtime field was not redacted: %s", resp.Body)
			}
		})
	}
}

func TestStrictJSONStringWhitespaceLimitedToFunctionArguments(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	strict := requestIntercept(t, formatOpenAIResponse, []byte(`{"input":[{"type":"local_shell_call_output","output":"   "}]}`))
	if !strict.Reject {
		t.Fatal("whitespace-only strict JSON output was accepted")
	}

	functionArgs := requestIntercept(t, formatOpenAIResponse, []byte(`{"input":[{"type":"function_call","arguments":"   "}]}`))
	if functionArgs.Reject {
		t.Fatalf("function argument whitespace compatibility changed: %s", functionArgs.RejectReason)
	}
}

func TestUnknownProviderContentBlockRejected(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	tests := []struct {
		format string
		body   string
	}{
		{format: formatOpenAI, body: `{"messages":[{"content":[{"type":"future_block","payload":"secret"}]}]}`},
		{format: formatOpenAIResponse, body: `{"input":[{"type":"future_block","payload":"secret"}]}`},
		{format: formatClaude, body: `{"messages":[{"content":[{"type":"future_block","payload":"secret"}]}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			resp := requestIntercept(t, tt.format, []byte(tt.body))
			if !resp.Reject {
				t.Fatalf("unknown content block must be rejected: %s", tt.body)
			}
			if strings.Contains(resp.RejectReason, "secret") {
				t.Fatalf("reject reason leaked block content: %q", resp.RejectReason)
			}
		})
	}
}

func TestResponsesNestedUnknownMembersRejected(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	tests := []string{
		`{"input":[{"type":"shell_call","action":{"commands":["echo ok"],"future":{"password":"plaintext-secret"}}}]}`,
		`{"input":[{"type":"shell_call_output","output":[{"stdout":"ok","stderr":"","outcome":{"type":"exit","exit_code":0},"future":{"password":"plaintext-secret"}}]}]}`,
		`{"input":[{"type":"apply_patch_call","operation":{"type":"delete_file","path":"file.txt","future":{"password":"plaintext-secret"}}}]}`,
		`{"input":[{"type":"code_interpreter_call","outputs":[{"type":"image","future":{"password":"plaintext-secret"}}]}]}`,
		`{"input":[{"type":"web_search_call","action":{"type":"open_page","future":{"password":"plaintext-secret"}}}]}`,
		`{"input":[{"type":"file_search_call","queries":["query"],"results":[{"text":"ok","future":{"password":"plaintext-secret"}}]}]}`,
	}
	for _, body := range tests {
		resp := requestIntercept(t, formatOpenAIResponse, []byte(body))
		if !resp.Reject {
			t.Fatalf("nested unknown member was accepted: %s", body)
		}
		if strings.Contains(resp.RejectReason, "plaintext-secret") || strings.Contains(resp.RejectReason, "future") {
			t.Fatalf("reject reason leaked nested input: %q", resp.RejectReason)
		}
	}
}

func TestCurrentOpenAISchemaFieldsAccepted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	tests := []struct {
		format string
		body   string
	}{
		{formatOpenAIResponse, `{"input":[{"role":"assistant","content":"ok","phase":"commentary"}]}`},
		{formatOpenAIResponse, `{"input":[{"type":"message","role":"assistant","content":"ok","phase":"final_answer"}]}`},
		{formatOpenAIResponse, `{"input":[{"type":"function_call","name":"run","arguments":"{}","namespace":"tools","caller":{"type":"direct"}}]}`},
		{formatOpenAIResponse, `{"input":[{"type":"function_call_output","output":"ok","caller":{"type":"direct"}}]}`},
		{formatOpenAIResponse, `{"input":[{"type":"custom_tool_call","name":"run","input":"ok","namespace":"tools","caller":{"type":"direct"}}]}`},
		{formatOpenAIResponse, `{"input":[{"type":"custom_tool_call_output","output":"ok","caller":{"type":"direct"}}]}`},
		{formatOpenAIResponse, `{"input":[{"type":"shell_call","action":{"commands":["echo ok"]},"environment":{"type":"local"},"caller":{"type":"direct"}}]}`},
		{formatOpenAIResponse, `{"input":[{"type":"shell_call_output","output":[{"stdout":"ok","stderr":"","outcome":{"type":"exit","exit_code":0}}],"caller":{"type":"direct"}}]}`},
		{formatOpenAIResponse, `{"input":[{"type":"apply_patch_call","operation":{"type":"delete_file","path":"file.txt"},"caller":{"type":"direct"}}]}`},
		{formatOpenAIResponse, `{"input":[{"type":"apply_patch_call_output","output":"ok","caller":{"type":"direct"}}]}`},
		{formatOpenAIResponse, `{"input":[{"role":"user","content":[{"type":"input_text","text":"ok","prompt_cache_breakpoint":{"mode":"explicit"}}]}]}`},
		{formatOpenAI, `{"messages":[{"role":"user","content":[{"type":"text","text":"ok","prompt_cache_breakpoint":{"mode":"explicit"}}]}]}`},
	}
	for _, tt := range tests {
		resp := requestIntercept(t, tt.format, []byte(tt.body))
		if resp.Reject {
			t.Fatalf("current schema field was rejected: format=%s reason=%q body=%s", tt.format, resp.RejectReason, tt.body)
		}
	}
}

// TestResponsesRealisticRequestsNotRejected feeds realistic full OpenAI
// Responses request bodies (as clients and the Codex translator actually
// produce them) through the fail-closed request interceptor. If any is
// rejected, the strict allow-list scanner is the empty-response root cause.
func TestResponsesRealisticRequestsNotRejected(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")

	cases := []struct {
		name string
		body string
	}{
		{
			name: "simple string input",
			body: `{"model":"gpt-5.2","input":"Say hello.","stream":true}`,
		},
		{
			name: "message array with input_text",
			body: `{"model":"gpt-5.2","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}],"stream":true}`,
		},
		{
			name: "reasoning + assistant output_text history",
			body: `{"model":"gpt-5.2","input":[` +
				`{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"enc"},` +
				`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"prior","annotations":[]}]},` +
				`{"type":"message","role":"user","content":[{"type":"input_text","text":"next"}]}],"stream":true}`,
		},
		{
			name: "function_call + function_call_output history",
			body: `{"model":"gpt-5.2","input":[` +
				`{"type":"function_call","call_id":"call_1","name":"get_weather","arguments":"{\"city\":\"SF\"}"},` +
				`{"type":"function_call_output","call_id":"call_1","output":"sunny"}],"stream":true}`,
		},
		{
			name: "tools + tool_choice + instructions",
			body: `{"model":"gpt-5.2","instructions":"be brief","input":"weather?","tools":[{"type":"function","name":"get_weather","parameters":{"type":"object"}}],"tool_choice":"auto","stream":true}`,
		},
		{
			name: "with metadata and top-level knobs",
			body: `{"model":"gpt-5.2","input":"hi","temperature":0.7,"top_p":1,"max_output_tokens":256,"metadata":{"user":"u1"},"parallel_tool_calls":true,"store":false,"stream":true}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := requestIntercept(t, formatOpenAIResponse, []byte(tc.body))
			if resp.Reject {
				t.Fatalf("request rejected (empty-response cause): %s", resp.RejectReason)
			}
			if len(resp.Body) > 0 && strings.Contains(string(resp.Body), "\x00") {
				t.Fatalf("unexpected body corruption")
			}
		})
	}
}
