package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/sirupsen/logrus"
)

func TestEndpointsScanContentAndSkipProtocolMetadata(t *testing.T) {
	logger := logrus.StandardLogger()
	previousOutput, previousLevel := logger.Out, logger.GetLevel()
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	logger.SetLevel(logrus.WarnLevel)
	t.Cleanup(func() {
		logger.SetOutput(previousOutput)
		logger.SetLevel(previousLevel)
	})

	cases := []struct {
		name, format, body string
	}{
		{
			"chat messages and blocks", formatOpenAI,
			`{"model":"OUTERSECRET","output_config":{"password":"OUTERSECRET"},"messages":[{"role":"user","future":"OUTERSECRET","content":[{"type":"text","text":"CONTENTSECRET","future":{"password":"OUTERSECRET"},"prompt_cache_breakpoint":42},{"type":"image_url","image_url":"OUTERSECRET","future":true}]}],"tools":[{"description":"OUTERSECRET","parameters":{"password":"OUTERSECRET"}}]}`,
		},
		{
			"chat tools and audio", formatOpenAI,
			`{"messages":[{"role":"assistant","content":null,"audio":{"transcript":"CONTENTSECRET","future":"OUTERSECRET"},"tool_calls":[{"type":"function","future":"OUTERSECRET","function":{"name":"OUTERSECRET","arguments":"{\"password\":\"CONTENTSECRET\"}","future":42}},{"type":"custom","future":"OUTERSECRET","custom":{"name":"OUTERSECRET","input":"CONTENTSECRET","future":42}}],"function_call":{"name":"OUTERSECRET","arguments":"{\"password\":\"CONTENTSECRET\"}","future":42}}]}`,
		},
		{
			"responses messages", formatOpenAIResponse,
			`{"instructions":"CONTENTSECRET","output_config":{"password":"OUTERSECRET"},"input":[{"id":"ref","future":"OUTERSECRET"},{"role":"user","content":"CONTENTSECRET","phase":42,"future":"OUTERSECRET"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"CONTENTSECRET","future":"OUTERSECRET"}],"phase":{},"future":true},{"type":"input_text","text":"CONTENTSECRET","prompt_cache_breakpoint":"OUTERSECRET","future":true}]}`,
		},
		{
			"responses tools", formatOpenAIResponse,
			`{"input":[{"type":"function_call","arguments":"{\"password\":\"CONTENTSECRET\"}","caller":{"type":"future","password":"OUTERSECRET"},"namespace":42,"future":true},{"type":"custom_tool_call","input":"CONTENTSECRET","caller":42,"namespace":{},"future":"OUTERSECRET"},{"type":"function_call_output","output":"CONTENTSECRET","caller":"OUTERSECRET","future":true},{"type":"mcp_call","arguments":"{\"password\":\"CONTENTSECRET\"}","output":"CONTENTSECRET","future":"OUTERSECRET"}]}`,
		},
		{
			"responses shell and search", formatOpenAIResponse,
			`{"input":[{"type":"shell_call","action":{"commands":["CONTENTSECRET"],"future":"OUTERSECRET"},"environment":{"type":"future","password":"OUTERSECRET"}},{"type":"shell_call_output","output":[{"stdout":"CONTENTSECRET","stderr":"","outcome":{"type":"future","password":"OUTERSECRET"},"future":true}]},{"type":"web_search_call","action":{"type":"search","query":"CONTENTSECRET","sources":"OUTERSECRET","future":42}},{"type":"file_search_call","queries":["CONTENTSECRET"],"results":[{"text":"CONTENTSECRET","attributes":{"password":"OUTERSECRET"},"future":true}]},{"type":"additional_tools","role":42,"tools":{"password":"OUTERSECRET"},"future":true}]}`,
		},
		{
			"claude content and tools", formatClaude,
			`{"system":[{"type":"text","text":"CONTENTSECRET","future":"OUTERSECRET"}],"output_config":{"password":"OUTERSECRET"},"messages":[{"role":"assistant","future":"OUTERSECRET","content":[{"type":"text","text":"CONTENTSECRET","future":{"password":"OUTERSECRET"}},{"type":"tool_use","input":{"password":"CONTENTSECRET"},"future":"OUTERSECRET"},{"type":"tool_search_tool_result","content":{"type":"tool_search_tool_search_result","tool_references":"OUTERSECRET"}}]}]}`,
		},
		{
			"gemini parts and tools", formatGemini,
			`{"generationConfig":{"password":"OUTERSECRET"},"systemInstruction":{"parts":[{"text":"CONTENTSECRET","future":"OUTERSECRET"}],"future":true},"system_instruction":{"parts":[{"text":"CONTENTSECRET"}],"future":42},"contents":[{"role":"user","future":"OUTERSECRET","parts":[{"text":"CONTENTSECRET","future":{"password":"OUTERSECRET"},"mediaResolution":42,"partMetadata":"OUTERSECRET"},{"inlineData":"OUTERSECRET"},{"future":"OUTERSECRET"},{"functionCall":{"args":{"password":"CONTENTSECRET"},"future":"OUTERSECRET","partialArgs":[{"stringValue":"CONTENTSECRET","future":true}]}},{"functionResponse":{"response":{"password":"CONTENTSECRET"},"future":"OUTERSECRET"}},{"toolCall":{"args":{"password":"CONTENTSECRET"},"future":"OUTERSECRET"}},{"toolResponse":{"response":{"password":"CONTENTSECRET"},"future":"OUTERSECRET"}}]}]}`,
		},
		{"image prompt", formatOpenAIImage, `{"prompt":"CONTENTSECRET","model":"OUTERSECRET","future":{"password":"OUTERSECRET"}}`},
		{"video prompt", formatOpenAIVideo, `{"prompt":"CONTENTSECRET","model":"OUTERSECRET","future":{"password":"OUTERSECRET"}}`},
	}
	for _, tc := range cases {
		for _, mode := range []string{modeFilter, modeBlock} {
			for _, hasContentMatch := range []bool{false, true} {
				name := tc.name + "/" + mode
				if hasContentMatch {
					name += "/content match"
				} else {
					name += "/metadata only"
				}
				t.Run(name, func(t *testing.T) {
					callRegister(t, pluginabi.MethodPluginRegister, "mode: "+mode+"\nbuiltin_rules_enabled: false\ncustom_field_rules:\n  - name: password\n    keys: [password]\n    regex: '^(CONTENTSECRET|OUTERSECRET)$'\ncustom_value_rules:\n  - name: marker\n    regex: '(CONTENTSECRET|OUTERSECRET)'\n")
					body := tc.body
					if !hasContentMatch {
						body = strings.ReplaceAll(body, "CONTENTSECRET", "ordinary text")
					}
					logs.Reset()
					resp := requestIntercept(t, tc.format, []byte(body))
					wantReject := hasContentMatch && mode == modeBlock
					if resp.Reject != wantReject {
						t.Fatalf("reject=%v, want %v: %s", resp.Reject, wantReject, resp.RejectReason)
					}
					if logs.Len() != 0 {
						t.Fatalf("protocol metadata triggered a warning: %s", logs.String())
					}
					if !hasContentMatch {
						if len(resp.Body) != 0 {
							t.Fatalf("metadata-only request was rewritten: %s", resp.Body)
						}
						return
					}
					if wantReject {
						if !strings.Contains(resp.RejectReason, "marker") && !strings.Contains(resp.RejectReason, "password") {
							t.Fatalf("rejection was not a content rule match: %s", resp.RejectReason)
						}
						return
					}
					if len(resp.Body) == 0 || bytes.Contains(resp.Body, []byte("CONTENTSECRET")) {
						t.Fatalf("known message content was not redacted: %s", resp.Body)
					}
					// Undo only the expected content replacements, then compare all
					// fields to catch any changed metadata or skipped content regions.
					normalized := testTokenRe.ReplaceAll(resp.Body, []byte("CONTENTSECRET"))
					var original, got any
					if err := json.Unmarshal([]byte(body), &original); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(normalized, &got); err != nil {
						t.Fatalf("rewritten JSON is invalid: %v", err)
					}
					if !reflect.DeepEqual(got, original) {
						t.Fatalf("fields outside content regions changed: got %s, want %s", normalized, body)
					}
				})
			}
		}
	}
}
