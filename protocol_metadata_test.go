package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
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
			"responses configuration updates", formatOpenAIResponse,
			`{"reasoning":{"effort":"medium"},"input":[{"type":"message","role":"user","content":"CONTENTSECRET"},{"type":"configuration_update","reasoning":{"effort":"OUTERSECRET"},"future":{"password":"OUTERSECRET"}},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"CONTENTSECRET"}]},{"type":"configuration_update","reasoning":{"effort":"high"}},{"type":"configuration_update"}]}`,
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
		{
			"unknown chat blocks", formatOpenAI,
			`{"messages":[{"content":[{"future":"OUTERSECRET"},{"type":42,"text":"OUTERSECRET"},{"type":"","text":"OUTERSECRET"},{"type":"future_block","text":"OUTERSECRET","password":"OUTERSECRET"},{"type":"text","text":"CONTENTSECRET"}]}]}`,
		},
		{
			"unknown chat tools", formatOpenAI,
			`{"messages":[{"tool_calls":[{"future":"OUTERSECRET"},{"type":null,"function":{"arguments":"OUTERSECRET"}},{"type":"future_tool","function":{"arguments":"OUTERSECRET"}},{"type":"function","function":{"arguments":"\"CONTENTSECRET\""}},{"function":{"arguments":"\"CONTENTSECRET\""}}]}]}`,
		},
		{
			"unknown responses items", formatOpenAIResponse,
			`{"instructions":"CONTENTSECRET","input":[{}, {"future":{"password":"OUTERSECRET"}}, {"type":42,"content":"OUTERSECRET"},{"type":"future_configuration_update","role":42,"content":"OUTERSECRET","reasoning":{"effort":"OUTERSECRET"}},{"type":"message","role":"user","content":"CONTENTSECRET"}]}`,
		},
		{
			"unknown responses blocks", formatOpenAIResponse,
			`{"input":[{"type":"message","content":[{"text":"OUTERSECRET"},{"type":{},"text":"OUTERSECRET"},{"type":"future_block","text":"OUTERSECRET","content":{"password":"OUTERSECRET"}},{"type":"configuration_update","reasoning":{"effort":"OUTERSECRET"}},{"type":"input_text","text":"CONTENTSECRET"}]},{"type":"function_call_output","output":[{"type":"future_block","text":"OUTERSECRET"},{"type":"output_text","text":"CONTENTSECRET"}]}]}`,
		},
		{
			"unknown responses actions", formatOpenAIResponse,
			`{"input":[{"type":"computer_call","action":{"type":"type","text":"CONTENTSECRET"},"actions":[{"type":"future_action","text":"OUTERSECRET"},{"type":"type","text":"CONTENTSECRET"}]},{"type":"local_shell_call","action":{"type":"future_action","command":"OUTERSECRET"}},{"type":"apply_patch_call","operation":{"type":"future_operation","diff":"OUTERSECRET"}},{"type":"web_search_call","action":{"type":"future_action","query":"OUTERSECRET"}},{"type":"message","content":"CONTENTSECRET"}]}`,
		},
		{
			"unknown code interpreter outputs", formatOpenAIResponse,
			`{"input":[{"type":"code_interpreter_call","code":"CONTENTSECRET","outputs":[{"type":"future_output","logs":"OUTERSECRET"},{"logs":"OUTERSECRET"},{"type":"logs","logs":"CONTENTSECRET"}]}]}`,
		},
		{
			"unknown claude blocks", formatClaude,
			`{"system":[{"type":"future_block","text":"OUTERSECRET"},{"type":"text","text":"CONTENTSECRET"}],"messages":[{"content":[{"text":"OUTERSECRET"},{"type":false,"text":"OUTERSECRET"},{"type":"future_block","input":{"password":"OUTERSECRET"}},{"type":"text","text":"CONTENTSECRET"}]}]}`,
		},
		{
			"unknown claude tool results", formatClaude,
			`{"messages":[{"content":[{"type":"tool_result","content":{"type":"future_result","stdout":"OUTERSECRET"}},{"type":"tool_result","content":{"stdout":"OUTERSECRET"}},{"type":"text_editor_code_execution_tool_result","content":{"type":"text_editor_code_execution_view_result","file_type":"future","content":{"password":"OUTERSECRET"}}},{"type":"tool_result","content":{"type":"code_execution_result","stdout":"CONTENTSECRET","stderr":""}}]}]}`,
		},
		{
			"unknown claude documents", formatClaude,
			`{"messages":[{"content":[{"type":"web_fetch_tool_result","content":{"type":"web_fetch_result","content":{"type":"future_document","text":"OUTERSECRET"}}},{"type":"document","title":"CONTENTSECRET","source":{"type":"future_source","data":"OUTERSECRET"}},{"type":"document","source":{"type":"content","content":[{"type":"future_block","text":"OUTERSECRET"},{"type":"text","text":"CONTENTSECRET"}]}}]}]}`,
		},
		{
			"unknown claude system and search blocks", formatClaude,
			`{"messages":[{"content":[{"type":"mid_conv_system","content":[{"type":"future_block","text":"OUTERSECRET"},{"type":"text","text":"CONTENTSECRET"}]},{"type":"tool_search_tool_result","content":{"type":"future_result","error_message":"OUTERSECRET"}},{"type":"text","text":"CONTENTSECRET"}]}]}`,
		},
		{"image prompt", formatOpenAIImage, `{"prompt":"CONTENTSECRET","model":"OUTERSECRET","future":{"password":"OUTERSECRET"}}`},
		{"video prompt", formatOpenAIVideo, `{"prompt":"CONTENTSECRET","model":"OUTERSECRET","future":{"password":"OUTERSECRET"}}`},
	}
	for _, tc := range cases {
		for _, method := range []string{pluginabi.MethodRequestInterceptBefore, pluginabi.MethodRequestInterceptAfter} {
			for _, mode := range []string{modeFilter, modeBlock} {
				for _, hasContentMatch := range []bool{false, true} {
					name := tc.name + "/" + method + "/" + mode
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
						resp := invokeRequestIntercept(t, method, tc.format, []byte(body))
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
}
