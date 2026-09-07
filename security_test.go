package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// TestForgedTokenSubstringStillRedacted covers fix #1: a field value that merely
// contains a token-shaped substring alongside a real secret must still be
// redacted. Only a value that is exactly one complete token is skipped.
func TestForgedTokenSubstringStillRedacted(t *testing.T) {
	body := []byte(`{"password":"hunter2 <REDACTED_0000000000000000>"}`)
	res := scanJSONObjectForTest(t, body, testRules(), testTokenRe, testRedact)
	var out map[string]any
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	got := out["password"].(string)
	if strings.Contains(got, "hunter2") {
		t.Fatalf("forged-token value leaked the secret: %q", got)
	}
	if !testTokenRe.MatchString(got) || testTokenRe.FindString(got) != got {
		t.Fatalf("value should be replaced with a single whole token: %q", got)
	}
	if len(res.Matches) != 1 || res.Matches[0].Rule != "password" {
		t.Fatalf("expected one password field match: %+v", res.Matches)
	}
}

func TestForgedWholeTokenCandidateIsRedacted(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	forged := "<sk-ABCDEFGHIJKLMNOPQRST_0000000000000000>"
	body := []byte(`{"messages":[{"role":"user","content":"` + forged + `"}]}`)

	response := requestIntercept(t, formatOpenAI, body)
	if response.Reject {
		t.Fatalf("request unexpectedly rejected: %s", response.RejectReason)
	}
	if len(response.Body) == 0 {
		t.Fatal("forged token candidate was forwarded unchanged")
	}
	if bytes.Contains(response.Body, []byte("sk-ABCDEFGHIJKLMNOPQRST")) {
		t.Fatalf("forged token candidate bypassed redaction: %s", response.Body)
	}
}

// TestCrossRequestAllowlistIsolation covers fix #2: a response for one request
// must not restore a token minted for a different request, even though both
// share the process vault.
func TestCrossRequestAllowlistIsolation(t *testing.T) {
	setSharedVault(newVault(100, time.Hour))
	label := "REDACTED"
	tokenRe := tokenPattern(label)

	secretA := "sk-aaaaaaaaaa0000000000"
	secretB := "sk-bbbbbbbbbb1111111111"
	tokenA := makeToken(label, secretA)
	tokenB := makeToken(label, secretB)
	getSharedVault().Put(tokenA, secretA)
	getSharedVault().Put(tokenB, secretB)

	// Request A only ever emitted tokenA, so its allowlist excludes tokenB.
	requestBodyA := []byte(`{"prompt":"` + tokenA + `"}`)
	allowed := collectTokens(requestBodyA, tokenRe, getSharedVault())

	// A malicious/mismatched response tries to smuggle tokenB back to caller A.
	responseBody := []byte(`{"answer":"` + tokenB + ` and ` + tokenA + `"}`)
	restored := string(restoreBody(responseBody, tokenRe, allowed, getSharedVault()))

	if strings.Contains(restored, secretB) {
		t.Fatalf("cross-request secret B leaked into response A: %q", restored)
	}
	if !strings.Contains(restored, secretA) {
		t.Fatalf("in-scope secret A should have been restored: %q", restored)
	}
	if !strings.Contains(restored, tokenB) {
		t.Fatalf("out-of-scope tokenB should be left verbatim: %q", restored)
	}
}

// TestStructuredRestoreEscaping covers fix #3: a secret containing characters
// that require JSON escaping (quote, backslash, newline) must round-trip
// through tokenization and restoration without corrupting the JSON document.
func TestStructuredRestoreEscaping(t *testing.T) {
	setSharedVault(newVault(100, time.Hour))
	label := "REDACTED"
	tokenRe := tokenPattern(label)

	secret := "line1\"quote\\back\nline2"
	token := makeToken(label, secret)
	getSharedVault().Put(token, secret)

	requestBody := []byte(`{"prompt":"` + token + `"}`)
	allowed := collectTokens(requestBody, tokenRe, getSharedVault())

	responseBody, _ := json.Marshal(map[string]any{"answer": token})
	restored := restoreBody(responseBody, tokenRe, allowed, getSharedVault())

	// The restored payload must remain valid JSON with the exact secret inside.
	var out map[string]any
	if err := json.Unmarshal(restored, &out); err != nil {
		t.Fatalf("restored body is not valid JSON: %v (%q)", err, restored)
	}
	if out["answer"] != secret {
		t.Fatalf("secret not restored exactly: %q", out["answer"])
	}
}

// TestStructuredRestoreSSEEscaping covers fix #3 for SSE frames: a token inside
// an SSE "data:" JSON frame is restored while keeping the frame valid.
func TestStructuredRestoreSSEEscaping(t *testing.T) {
	setSharedVault(newVault(100, time.Hour))
	label := "REDACTED"
	tokenRe := tokenPattern(label)

	secret := `has "quote" and \slash`
	token := makeToken(label, secret)
	getSharedVault().Put(token, secret)

	requestBody := []byte(`{"prompt":"` + token + `"}`)
	allowed := collectTokens(requestBody, tokenRe, getSharedVault())

	frameJSON, _ := json.Marshal(map[string]any{"delta": token})
	sse := []byte("data: " + string(frameJSON) + "\n\n")
	restored := restoreBody(sse, tokenRe, allowed, getSharedVault())

	if !strings.HasPrefix(string(restored), "data: ") {
		t.Fatalf("SSE framing not preserved: %q", restored)
	}
	payload := strings.TrimSpace(strings.TrimPrefix(string(restored), "data:"))
	var out map[string]any
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		t.Fatalf("restored SSE frame is not valid JSON: %v (%q)", err, payload)
	}
	if out["delta"] != secret {
		t.Fatalf("secret not restored exactly in SSE frame: %q", out["delta"])
	}
}

func TestSSELineEndingsPreserved(t *testing.T) {
	setSharedVault(newVault(100, time.Hour))
	tokenRe := restoreTokenPattern()
	secret := "line-ending-secret"
	token := makeToken("REDACTED", secret)
	getSharedVault().Put(token, secret)
	allowed := collectTokens([]byte(token), tokenRe, getSharedVault())

	for _, tt := range []struct {
		name string
		sep  string
	}{
		{name: "CRLF", sep: "\r\n"},
		{name: "CR", sep: "\r"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte("event: message" + tt.sep + `data: {"delta":"` + token + `"}` + tt.sep + tt.sep + `data: {"delta":"` + token + `"}` + tt.sep + tt.sep)
			restored := restoreBody(body, tokenRe, allowed, getSharedVault())
			if strings.Contains(string(restored), token) || strings.Count(string(restored), secret) != 2 {
				t.Fatalf("all SSE events were not restored: %q", restored)
			}
			withoutSep := strings.ReplaceAll(string(restored), tt.sep, "")
			if strings.ContainsAny(withoutSep, "\r\n") {
				t.Fatalf("SSE line ending changed from %q: %q", tt.sep, restored)
			}
			if strings.Count(string(restored), tt.sep) != strings.Count(string(body), tt.sep) {
				t.Fatalf("SSE delimiter count changed: got=%q want=%q", restored, body)
			}
		})
	}
}

func TestScalarJSONRestoreEscaping(t *testing.T) {
	setSharedVault(newVault(100, time.Hour))
	tokenRe := restoreTokenPattern()
	secret := "scalar\"quote\\slash\nline2"
	token := makeToken("REDACTED", secret)
	getSharedVault().Put(token, secret)
	allowed := collectTokens([]byte(token), tokenRe, getSharedVault())

	for _, body := range [][]byte{
		[]byte(`"` + token + `"`),
		mustJSONMarshal(t, token),
	} {
		restored := restoreBody(body, tokenRe, allowed, getSharedVault())
		var got string
		if err := json.Unmarshal(restored, &got); err != nil {
			t.Fatalf("restored scalar is invalid JSON: %v (%q)", err, restored)
		}
		if got != secret {
			t.Fatalf("scalar secret not restored exactly: %q", got)
		}
	}
}

func TestScalarJSONSSERestoreEscaping(t *testing.T) {
	setSharedVault(newVault(100, time.Hour))
	tokenRe := restoreTokenPattern()
	secret := "scalar SSE \"quote\" \\slash\nline2"
	token := makeToken("REDACTED", secret)
	getSharedVault().Put(token, secret)
	allowed := collectTokens([]byte(token), tokenRe, getSharedVault())
	body := append([]byte("data: "), mustJSONMarshal(t, token)...)
	body = append(body, '\n', '\n')

	restored := restoreBody(body, tokenRe, allowed, getSharedVault())
	payload := strings.TrimSpace(strings.TrimPrefix(string(restored), "data:"))
	var got string
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatalf("restored scalar SSE is invalid JSON: %v (%q)", err, restored)
	}
	if got != secret {
		t.Fatalf("scalar SSE secret not restored exactly: %q", got)
	}
}

func TestMalformedJSONResponseRemainsUnchanged(t *testing.T) {
	setSharedVault(newVault(100, time.Hour))
	tokenRe := restoreTokenPattern()
	secret := "quote\"slash\\newline\n"
	token := makeToken("REDACTED", secret)
	getSharedVault().Put(token, secret)
	allowed := collectTokens([]byte(token), tokenRe, getSharedVault())
	body := []byte(`{"value":"` + token + `"} ]`)

	if got := restoreBody(body, tokenRe, allowed, getSharedVault()); string(got) != string(body) {
		t.Fatalf("malformed JSON-looking response was modified: got=%q want=%q", got, body)
	}
}

func TestMalformedJSONSSEPayloadRemainsUnchanged(t *testing.T) {
	setSharedVault(newVault(100, time.Hour))
	tokenRe := restoreTokenPattern()
	secret := "quote\"slash\\newline\n"
	token := makeToken("REDACTED", secret)
	getSharedVault().Put(token, secret)
	allowed := collectTokens([]byte(token), tokenRe, getSharedVault())
	body := []byte(`data: {"value":"` + token + `"} ]` + "\n\n")

	if got := restoreBody(body, tokenRe, allowed, getSharedVault()); string(got) != string(body) {
		t.Fatalf("malformed JSON-looking SSE payload was modified: got=%q want=%q", got, body)
	}
}

func TestSplitSSEJSONLineBufferedAtEveryTokenBoundary(t *testing.T) {
	setSharedVault(newVault(100, time.Hour))
	tokenRe := restoreTokenPattern()
	secret := "line1\"quote\\slash\nline2"
	token := makeToken("REDACTED", secret)
	getSharedVault().Put(token, secret)
	allowed := collectTokens([]byte(token), tokenRe, getSharedVault())

	escapedFrame := string(mustJSONMarshal(t, map[string]any{"delta": token}))
	escapedSplit := strings.Index(escapedFrame, "REDACTED")
	if escapedSplit < 0 {
		t.Fatalf("escaped frame does not contain token label: %q", escapedFrame)
	}
	tests := []struct {
		name   string
		first  string
		second string
	}{
		{name: "before token", first: `data: {"delta":"`, second: token + `"}` + "\n\n"},
		{name: "inside escaped token", first: "data: " + escapedFrame[:escapedSplit+4], second: escapedFrame[escapedSplit+4:] + "\n\n"},
		{name: "after token before JSON close", first: `data: {"delta":"` + token, second: `"}` + "\n\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "sse-boundary-" + tt.name
			streamCarry.reset(key)
			out1, drop1 := detokenizeStreamChunk(key, []byte(tt.first), tokenRe, []string{"REDACTED"}, allowed, getSharedVault(), true)
			if !drop1 || len(out1) != 0 {
				t.Fatalf("incomplete JSON data line must be fully withheld: drop=%v out=%q", drop1, out1)
			}
			out2, drop2 := detokenizeStreamChunk(key, []byte(tt.second), tokenRe, []string{"REDACTED"}, allowed, getSharedVault(), true)
			if drop2 {
				t.Fatal("completed JSON data line must be emitted")
			}
			payload := strings.TrimSpace(strings.TrimPrefix(string(out2), "data:"))
			var decoded map[string]any
			if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
				t.Fatalf("restored SSE payload is invalid JSON: %v (%q)", err, payload)
			}
			if decoded["delta"] != secret {
				t.Fatalf("SSE secret not restored exactly: %q", decoded["delta"])
			}
		})
	}
}

func TestSplitSSEDataPrefixIsBuffered(t *testing.T) {
	setSharedVault(newVault(100, time.Hour))
	secret := "line1\"quote\\slash\nline2"
	token := makeToken("REDACTED", secret)
	getSharedVault().Put(token, secret)
	tokenRe := restoreTokenPattern()
	allowed := collectTokens([]byte(token), tokenRe, getSharedVault())
	key := "split-sse-data-prefix"
	streamCarry.reset(key)

	out1, drop1 := detokenizeStreamChunk(key, []byte("da"), tokenRe, []string{"REDACTED"}, allowed, getSharedVault(), true)
	if !drop1 || len(out1) != 0 {
		t.Fatalf("partial SSE data prefix must be withheld: drop=%v out=%q", drop1, out1)
	}
	out2, drop2 := detokenizeStreamChunk(key, []byte(`ta: {"delta":"`+token+`"}`+"\n\n"), tokenRe, []string{"REDACTED"}, allowed, getSharedVault(), true)
	if drop2 {
		t.Fatal("completed SSE line must be emitted")
	}
	payload := strings.TrimSpace(strings.TrimPrefix(string(out2), "data:"))
	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("restored split-prefix SSE payload is invalid JSON: %v (%q)", err, payload)
	}
	if decoded["delta"] != secret {
		t.Fatalf("split-prefix SSE secret not restored exactly: %q", decoded["delta"])
	}
}

func TestSemanticSSEEventWaitsForBlankSeparator(t *testing.T) {
	for _, tt := range []struct {
		name       string
		lineEnding string
	}{
		{name: "LF", lineEnding: "\n"},
		{name: "CRLF", lineEnding: "\r\n"},
		{name: "CR", lineEnding: "\r"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			callRegister(t, pluginabi.MethodPluginRegister, "")
			st := activeSnapshot()
			secret := "separator-boundary-secret-" + tt.name
			token := makeToken(st.label, secret)
			st.vault.Put(token, secret)
			requestBody := []byte(`{"input":"` + token + `"}`)
			resetStreamCarry(requestBody)

			payload, ok := encodeSemanticJSON(map[string]any{
				"type":          "response.output_text.delta",
				"output_index":  0,
				"content_index": 0,
				"delta":         token,
			})
			if !ok {
				t.Fatal("encode Responses event")
			}
			firstBody := []byte("event: response.output_text.delta" + tt.lineEnding + "data: " + string(payload) + tt.lineEnding)
			first := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, firstBody)
			if !first.DropChunk || len(first.Body) != 0 {
				t.Fatalf("SSE event was delivered before its blank separator: %+v", first)
			}

			separator := []byte(tt.lineEnding)
			second := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, separator)
			delivered := deliveredStreamBody(second, separator)
			if second.DropChunk || openAIResponsesStreamText(t, delivered) != secret {
				t.Fatalf("completed SSE event was not restored: response=%+v delivered=%q", second, delivered)
			}
			frames := parseSemanticSSEFrames(delivered)
			if len(frames) != 1 || frames[0].event != "response.output_text.delta" || !bytes.Equal(frames[0].lineEnding, []byte(tt.lineEnding)) {
				t.Fatalf("SSE event framing changed across separator boundary: %q", delivered)
			}
		})
	}
}

func TestGeminiBareJSONUnderSSEHeaderDoesNotWaitForSeparator(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "gemini-bare-no-separator-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"contents":[{"parts":[{"text":"` + token + `"}]}]}`)
	resetStreamCarry(requestBody)
	body := geminiBody(t, token)

	response := invokeStreamBody(t, formatGemini, requestBody, 0, body)
	if response.DropChunk {
		t.Fatal("complete Gemini bare JSON was mistaken for an incomplete SSE event")
	}
	if got := geminiStreamText(t, deliveredStreamBody(response, body)); got != secret {
		t.Fatalf("Gemini bare JSON was not restored immediately: %q", got)
	}
}

func TestSSEPrefixCarryRequiresEventStreamContentType(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "line1\"quote\\slash\nline2"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"message":"` + token + `"}`)
	streamID := streamKey(requestBody)
	initStreamWithID(t, formatOpenAIResponse, streamID, requestBody)

	invoke := func(index int, body []byte, contentType string) pluginapi.StreamChunkInterceptResponse {
		t.Helper()
		req, _ := json.Marshal(pluginapi.StreamChunkInterceptRequest{
			RequestID:       streamID,
			Body:            body,
			ChunkIndex:      index,
			ResponseHeaders: http.Header{"Content-Type": []string{contentType}},
		})
		raw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, req)
		if err != nil {
			t.Fatalf("stream intercept: %v", err)
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("unmarshal envelope: %v", err)
		}
		var response pluginapi.StreamChunkInterceptResponse
		if err := json.Unmarshal(env.Result, &response); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		return response
	}

	plain := invoke(0, []byte("da"), "application/octet-stream")
	if plain.DropChunk || len(plain.Body) != 0 {
		t.Fatalf("non-SSE data prefix was withheld or modified: %+v", plain)
	}

	resetStreamCarry(requestBody)
	initStreamWithID(t, formatOpenAIResponse, streamID, requestBody)
	first := invoke(0, []byte("da"), "text/event-stream; charset=utf-8")
	if !first.DropChunk {
		t.Fatalf("SSE data prefix was not withheld: %+v", first)
	}
	second := invoke(1, []byte(`ta: {"delta":"`+token+`"}`+"\n\n"), "text/event-stream; charset=utf-8")
	if second.DropChunk || !strings.Contains(string(second.Body), "line1") {
		t.Fatalf("SSE split prefix was not restored: %+v", second)
	}
}

func TestOversizedSSECarryIsNotRetained(t *testing.T) {
	store := newStreamStore()
	oversized := bytes.Repeat([]byte{'x'}, streamCarryMaxBytes+1)
	if store.setCarry("oversized-direct", oversized) {
		t.Fatal("oversized carry was accepted")
	}
	if carried := store.takeCarry("oversized-direct"); len(carried) != 0 {
		t.Fatalf("oversized carry was retained: %d bytes", len(carried))
	}

	key := "oversized-sse-line"
	streamCarry.reset(key)
	chunk := append([]byte(`data: "`), oversized...)
	out, drop := detokenizeStreamChunk(key, chunk, restoreTokenPattern(), nil, nil, newVault(1, time.Hour), true)
	if drop || string(out) != string(chunk) {
		t.Fatalf("oversized incomplete SSE line must pass unchanged: drop=%v out_len=%d", drop, len(out))
	}
	if carried := streamCarry.takeCarry(key); len(carried) != 0 {
		t.Fatalf("oversized SSE line remained in stream state: %d bytes", len(carried))
	}
}

func TestStreamRestorationToEmptyDropsChunk(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	token := makeToken(st.label, "")
	st.vault.Put(token, "")
	requestBody := []byte(`{"message":"` + token + `"}`)
	streamID := streamKey(requestBody)
	initStreamWithID(t, formatOpenAIResponse, streamID, requestBody)
	req, err := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:  streamID,
		Body:       []byte(token),
		ChunkIndex: 0,
	})
	if err != nil {
		t.Fatalf("marshal stream request: %v", err)
	}
	raw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, req)
	if err != nil {
		t.Fatalf("stream intercept: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	var resp pluginapi.StreamChunkInterceptResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("unmarshal stream response: %v", err)
	}
	if !resp.DropChunk {
		t.Fatalf("empty restored chunk was not dropped: %+v", resp)
	}
}

func TestEscapedRequestTokenAllowsStreamRestoration(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "escaped-request-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	escapedToken := strings.ReplaceAll(strings.ReplaceAll(token, "<", `\u003c`), ">", `\u003e`)
	requestBody := []byte(`{"message":"` + escapedToken + `"}`)
	streamID := streamKey(requestBody)
	initStreamWithID(t, formatOpenAIResponse, streamID, requestBody)

	req, err := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:  streamID,
		Body:       []byte(token),
		ChunkIndex: 0,
	})
	if err != nil {
		t.Fatalf("marshal stream request: %v", err)
	}
	raw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, req)
	if err != nil {
		t.Fatalf("stream intercept: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	var resp pluginapi.StreamChunkInterceptResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("unmarshal stream response: %v", err)
	}
	if resp.DropChunk || string(resp.Body) != secret {
		t.Fatalf("escaped request token did not enable restoration: %+v", resp)
	}
}

func TestPlainTextResponseWithJSONPrefixRestored(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "raw-response-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"message":"` + token + `"}`)
	body := []byte("200 OK " + token)

	req, err := json.Marshal(pluginapi.ResponseInterceptRequest{
		RequestBody:     requestBody,
		Body:            body,
		ResponseHeaders: http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
	})
	if err != nil {
		t.Fatalf("marshal response request: %v", err)
	}
	raw, err := handleMethod(pluginabi.MethodResponseInterceptAfter, req)
	if err != nil {
		t.Fatalf("response intercept: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	var resp pluginapi.ResponseInterceptResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if got := string(resp.Body); got != "200 OK "+secret {
		t.Fatalf("plain text response was not restored: got %q", got)
	}
}

func TestNonStreamOpenAIChatArgumentRestoration(t *testing.T) {
	testNonStreamArgumentRestoration(t, formatOpenAI,
		func(argument, outer string) map[string]any {
			return map[string]any{
				"summary": outer,
				"choices": []any{map[string]any{
					"message": map[string]any{"tool_calls": []any{map[string]any{
						"function": map[string]any{"arguments": argument},
					}}},
				}},
			}
		},
		func(doc map[string]any) string {
			choice := doc["choices"].([]any)[0].(map[string]any)
			message := choice["message"].(map[string]any)
			toolCall := message["tool_calls"].([]any)[0].(map[string]any)
			function := toolCall["function"].(map[string]any)
			return function["arguments"].(string)
		},
	)
}

func TestNonStreamOpenAIResponsesArgumentRestoration(t *testing.T) {
	testNonStreamArgumentRestoration(t, formatOpenAIResponse,
		func(argument, outer string) map[string]any {
			return map[string]any{
				"summary": outer,
				"output": []any{map[string]any{
					"type": "function_call", "arguments": argument,
				}},
			}
		},
		func(doc map[string]any) string {
			output := doc["output"].([]any)[0].(map[string]any)
			return output["arguments"].(string)
		},
	)
}

func TestNonStreamArgumentRestorationKeepsFieldsBeforeMalformedSibling(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "quote=\" slash=\\ line=\n control=\x01"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	malformed := `{"value":"` + token

	tests := []struct {
		name         string
		sourceFormat string
		body         map[string]any
		argumentFrom func(map[string]any) string
	}{
		{
			name: "Chat malformed choice sibling", sourceFormat: formatOpenAI,
			body: map[string]any{
				"summary": token,
				"choices": []any{
					map[string]any{"message": map[string]any{"tool_calls": []any{
						map[string]any{"function": map[string]any{"arguments": malformed}},
					}}},
					"malformed-choice",
				},
			},
			argumentFrom: func(root map[string]any) string {
				choice := root["choices"].([]any)[0].(map[string]any)
				message := choice["message"].(map[string]any)
				toolCall := message["tool_calls"].([]any)[0].(map[string]any)
				return toolCall["function"].(map[string]any)["arguments"].(string)
			},
		},
		{
			name: "Responses malformed output sibling", sourceFormat: formatOpenAIResponse,
			body: map[string]any{
				"summary": token,
				"output": []any{
					map[string]any{"type": "function_call", "arguments": malformed},
					"malformed-output",
				},
			},
			argumentFrom: func(root map[string]any) string {
				return root["output"].([]any)[0].(map[string]any)["arguments"].(string)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := mustJSONMarshal(t, test.body)
			delivered := invokeNonStreamResponseBody(t, test.sourceFormat, requestBody, body)
			doc, ok := decodeOneJSON(delivered)
			if !ok {
				t.Fatalf("mixed malformed response is invalid outer JSON: %q", delivered)
			}
			root := doc.(map[string]any)
			if got := test.argumentFrom(root); got != malformed {
				t.Fatalf("malformed arguments changed after malformed sibling: got %q want %q", got, malformed)
			}
			if got := root["summary"]; got != secret {
				t.Fatalf("ordinary outer field = %#v, want %q", got, secret)
			}
		})
	}
}

func testNonStreamArgumentRestoration(t *testing.T, sourceFormat string, makeBody func(argument, outer string) map[string]any, argumentFrom func(map[string]any) string) {
	t.Helper()
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "quote=\" slash=\\ line=\n tab=\t control=\x01 unicode=世界 html=<>&"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)

	t.Run("special characters and outer field", func(t *testing.T) {
		body := mustJSONMarshal(t, makeBody(`{"value":"`+token+`"}`, token))
		delivered := invokeNonStreamResponseBody(t, sourceFormat, requestBody, body)
		doc, ok := decodeOneJSON(delivered)
		if !ok {
			t.Fatalf("restored non-stream body is invalid JSON: %q", delivered)
		}
		root := doc.(map[string]any)
		if got := root["summary"]; got != secret {
			t.Fatalf("ordinary outer string restoration = %#v, want %q", got, secret)
		}
		argument := argumentFrom(root)
		var decoded map[string]string
		if err := json.Unmarshal([]byte(argument), &decoded); err != nil {
			t.Fatalf("restored non-stream arguments are invalid JSON %q: %v", argument, err)
		}
		if got := decoded["value"]; got != secret {
			t.Fatalf("restored non-stream argument value = %q, want %q", got, secret)
		}
	})

	t.Run("malformed arguments remain unchanged", func(t *testing.T) {
		malformed := `{"value":"` + token
		body := mustJSONMarshal(t, makeBody(malformed, token))
		delivered := invokeNonStreamResponseBody(t, sourceFormat, requestBody, body)
		doc, ok := decodeOneJSON(delivered)
		if !ok {
			t.Fatalf("response with malformed inner arguments is invalid outer JSON: %q", delivered)
		}
		root := doc.(map[string]any)
		if got := argumentFrom(root); got != malformed {
			t.Fatalf("malformed arguments changed: got %q want %q", got, malformed)
		}
		if got := root["summary"]; got != secret {
			t.Fatalf("ordinary outer string was not restored beside malformed arguments: %#v", got)
		}
	})
}

func invokeNonStreamResponseBody(t *testing.T, sourceFormat string, requestBody, body []byte) []byte {
	t.Helper()
	req := mustJSONMarshal(t, pluginapi.ResponseInterceptRequest{
		SourceFormat:    sourceFormat,
		RequestBody:     requestBody,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
		Body:            body,
	})
	raw, err := handleMethod(pluginabi.MethodResponseInterceptAfter, req)
	if err != nil {
		t.Fatalf("non-stream response intercept: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal non-stream envelope: %v", err)
	}
	var response pluginapi.ResponseInterceptResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("unmarshal non-stream response: %v", err)
	}
	if len(response.Body) == 0 {
		return body
	}
	return response.Body
}

func mustJSONMarshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return raw
}

func openAIChatToolArgumentBody(t *testing.T, choiceIndex, toolIndex int, fragment string, finishReason any) []byte {
	t.Helper()
	return mustJSONMarshal(t, map[string]any{
		"object": "chat.completion.chunk",
		"choices": []any{map[string]any{
			"index": choiceIndex,
			"delta": map[string]any{"tool_calls": []any{map[string]any{
				"index":    toolIndex,
				"function": map[string]any{"arguments": fragment},
			}}},
			"finish_reason": finishReason,
		}},
	})
}

func openAIChatToolArgumentSSEBody(t *testing.T, choiceIndex, toolIndex int, fragment string, finishReason any) []byte {
	t.Helper()
	body := append([]byte("data: "), openAIChatToolArgumentBody(t, choiceIndex, toolIndex, fragment, finishReason)...)
	return append(body, '\n', '\n')
}

func openAIChatToolArguments(t *testing.T, body []byte) map[string]string {
	t.Helper()
	arguments := make(map[string]string)
	for start := 0; start < len(body); {
		line, _, next := nextSSELine(body, start)
		start = next
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		var chunk struct {
			Choices []struct {
				Index int `json:"index"`
				Delta struct {
					ToolCalls []struct {
						Index    int `json:"index"`
						Function struct {
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(payload, &chunk); err != nil {
			t.Fatalf("invalid OpenAI Chat SSE frame: %v (%q)", err, payload)
		}
		for _, choice := range chunk.Choices {
			for _, tool := range choice.Delta.ToolCalls {
				channel := fmt.Sprintf("%d:%d", choice.Index, tool.Index)
				arguments[channel] += tool.Function.Arguments
			}
		}
	}
	return arguments
}

func responsesFunctionArgumentDelta(t *testing.T, outputIndex int, itemID, fragment string) []byte {
	t.Helper()
	return mustJSONMarshal(t, map[string]any{
		"type":         "response.function_call_arguments.delta",
		"output_index": outputIndex,
		"item_id":      itemID,
		"delta":        fragment,
	})
}

func responsesFunctionArgumentDone(t *testing.T, outputIndex int, itemID, arguments string) []byte {
	t.Helper()
	return mustJSONMarshal(t, map[string]any{
		"type":         "response.function_call_arguments.done",
		"output_index": outputIndex,
		"item_id":      itemID,
		"arguments":    arguments,
	})
}

func responsesFunctionArgumentSSEBody(event string, payload []byte) []byte {
	body := []byte("event: " + event + "\ndata: ")
	body = append(body, payload...)
	return append(body, '\n', '\n')
}

func openAIResponsesFunctionArgumentDeltas(t *testing.T, body []byte) map[string]string {
	t.Helper()
	deltas := make(map[string]string)
	for _, doc := range openAIResponsesEventDocs(t, body) {
		if doc["type"] != "response.function_call_arguments.delta" {
			continue
		}
		outputIndex, ok := nonnegativeJSONIndex(doc["output_index"])
		itemID, itemOK := doc["item_id"].(string)
		delta, deltaOK := doc["delta"].(string)
		if ok && itemOK && deltaOK {
			deltas[fmt.Sprintf("%d:%s", outputIndex, itemID)] += delta
		}
	}
	return deltas
}

func openAIResponsesEventDocs(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var docs []map[string]any
	for start := 0; start < len(body); {
		line, _, next := nextSSELine(body, start)
		start = next
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		doc, ok := decodeOneJSON(payload)
		if !ok {
			t.Fatalf("invalid OpenAI Responses event payload %q", payload)
		}
		root, ok := doc.(map[string]any)
		if !ok {
			t.Fatalf("OpenAI Responses event is not an object: %#v", doc)
		}
		docs = append(docs, root)
	}
	return docs
}

func findOpenAIResponsesEvent(t *testing.T, body []byte, eventType string) map[string]any {
	t.Helper()
	for _, doc := range openAIResponsesEventDocs(t, body) {
		if doc["type"] == eventType {
			return doc
		}
	}
	t.Fatalf("OpenAI Responses event %q not found in %q", eventType, body)
	return nil
}

func TestOpenAIChatToolArgumentRestoresAtEveryTokenSplit(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "openai-tool-split-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)

	for split := 0; split <= len(token); split++ {
		resetStreamCarry(requestBody)
		firstBody := openAIChatToolArgumentSSEBody(t, 0, 1, `{"value":"`+token[:split], nil)
		first := invokeStreamBody(t, formatOpenAI, requestBody, 0, firstBody)
		secondBody := openAIChatToolArgumentSSEBody(t, 0, 1, token[split:]+`"}`, nil)
		second := invokeStreamBody(t, formatOpenAI, requestBody, 1, secondBody)
		delivered := append(deliveredStreamBody(first, firstBody), deliveredStreamBody(second, secondBody)...)
		argument := openAIChatToolArguments(t, delivered)["0:1"]
		var decoded map[string]string
		if err := json.Unmarshal([]byte(argument), &decoded); err != nil {
			t.Fatalf("split %d produced invalid arguments %q: %v", split, argument, err)
		}
		if got := decoded["value"]; got != secret {
			t.Fatalf("split %d restored value = %q, want %q", split, got, secret)
		}
	}
}

func TestOpenAIChatToolArgumentChannelsRemainIsolated(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	type toolCase struct {
		choice int
		tool   int
		secret string
		token  string
	}
	cases := []toolCase{
		{choice: 1, tool: 0, secret: "choice-1-tool-0"},
		{choice: 1, tool: 3, secret: "choice-1-tool-3"},
		{choice: 7, tool: 0, secret: "choice-7-tool-0"},
		{choice: 7, tool: 3, secret: "choice-7-tool-3"},
	}
	var requestTokens strings.Builder
	for i := range cases {
		cases[i].token = makeToken(st.label, cases[i].secret)
		st.vault.Put(cases[i].token, cases[i].secret)
		requestTokens.WriteString(cases[i].token)
	}
	requestBody := []byte(`{"messages":[{"content":"` + requestTokens.String() + `"}]}`)
	resetStreamCarry(requestBody)

	var delivered []byte
	chunkIndex := 0
	for _, tc := range cases {
		split := len(tc.token) / 2
		body := openAIChatToolArgumentSSEBody(t, tc.choice, tc.tool, `{"value":"`+tc.token[:split], nil)
		response := invokeStreamBody(t, formatOpenAI, requestBody, chunkIndex, body)
		delivered = append(delivered, deliveredStreamBody(response, body)...)
		chunkIndex++
	}
	for i := len(cases) - 1; i >= 0; i-- {
		tc := cases[i]
		split := len(tc.token) / 2
		body := openAIChatToolArgumentSSEBody(t, tc.choice, tc.tool, tc.token[split:]+`"}`, nil)
		response := invokeStreamBody(t, formatOpenAI, requestBody, chunkIndex, body)
		delivered = append(delivered, deliveredStreamBody(response, body)...)
		chunkIndex++
	}

	arguments := openAIChatToolArguments(t, delivered)
	for _, tc := range cases {
		channel := fmt.Sprintf("%d:%d", tc.choice, tc.tool)
		var decoded map[string]string
		if err := json.Unmarshal([]byte(arguments[channel]), &decoded); err != nil {
			t.Fatalf("channel %s produced invalid arguments %q: %v", channel, arguments[channel], err)
		}
		if got := decoded["value"]; got != tc.secret {
			t.Fatalf("channel %s restored value = %q, want %q", channel, got, tc.secret)
		}
	}
}

func TestOpenAIChatFinishFlushesAllToolArguments(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "openai-finish-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	partial := token[:len(token)/2]

	var delivered []byte
	for tool := 0; tool < 2; tool++ {
		body := openAIChatToolArgumentSSEBody(t, 4, tool, `{"value":"`+partial, nil)
		response := invokeStreamBody(t, formatOpenAI, requestBody, tool, body)
		delivered = append(delivered, deliveredStreamBody(response, body)...)
	}
	finishPayload := mustJSONMarshal(t, map[string]any{
		"object": "chat.completion.chunk",
		"choices": []any{map[string]any{
			"index": 4, "delta": map[string]any{}, "finish_reason": "stop",
		}},
	})
	finishBody := append([]byte("data: "), finishPayload...)
	finishBody = append(finishBody, '\n', '\n')
	finish := invokeStreamBody(t, formatOpenAI, requestBody, 2, finishBody)
	finishDelivered := deliveredStreamBody(finish, finishBody)
	flushed := openAIChatToolArguments(t, finishDelivered)
	for tool := 0; tool < 2; tool++ {
		channel := fmt.Sprintf("4:%d", tool)
		if got := flushed[channel]; got != partial {
			t.Fatalf("finish event flush for channel %s = %q, want %q", channel, got, partial)
		}
	}
	delivered = append(delivered, finishDelivered...)

	arguments := openAIChatToolArguments(t, delivered)
	for tool := 0; tool < 2; tool++ {
		channel := fmt.Sprintf("4:%d", tool)
		if got, want := arguments[channel], `{"value":"`+partial; got != want {
			t.Fatalf("finish flush for channel %s = %q, want %q", channel, got, want)
		}
	}
	streamCarry.mu.Lock()
	defer streamCarry.mu.Unlock()
	if entry := streamCarry.entries[streamKey(requestBody)]; entry != nil && len(entry.arguments) != 0 {
		t.Fatalf("finish retained argument state: %#v", entry.arguments)
	}
}

func TestOpenAIChatSameFrameArgumentFinishPreservesSourceOrder(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "chat-same-frame-terminal-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	partial := token[:len(token)/2]

	t.Run("single tool", func(t *testing.T) {
		resetStreamCarry(requestBody)
		fragment := `{"value":"` + partial
		body := openAIChatToolArgumentSSEBody(t, 0, 0, fragment, "tool_calls")
		response := invokeStreamBody(t, formatOpenAI, requestBody, 0, body)
		delivered := deliveredStreamBody(response, body)
		if got := openAIChatToolArguments(t, delivered)["0:0"]; got != fragment {
			t.Fatalf("same-frame terminal argument = %q, want source order %q", got, fragment)
		}
		if frames := parseSemanticSSEFrames(delivered); len(frames) != 1 {
			t.Fatalf("same-frame terminal emitted %d frames, want no synthetic frame", len(frames))
		}
	})

	t.Run("multiple tools keep only prior channel synthetic", func(t *testing.T) {
		resetStreamCarry(requestBody)
		priorFragment := `{"prior":"` + partial
		priorBody := openAIChatToolArgumentSSEBody(t, 3, 0, priorFragment, nil)
		priorResponse := invokeStreamBody(t, formatOpenAI, requestBody, 0, priorBody)
		priorDelivered := deliveredStreamBody(priorResponse, priorBody)

		firstCurrent := `{"first":"` + partial
		secondCurrent := `{"second":"` + partial
		terminalPayload := mustJSONMarshal(t, map[string]any{
			"object": "chat.completion.chunk",
			"choices": []any{map[string]any{
				"index": 3,
				"delta": map[string]any{"tool_calls": []any{
					map[string]any{"index": 1, "function": map[string]any{"arguments": firstCurrent}},
					map[string]any{"index": 2, "function": map[string]any{"arguments": secondCurrent}},
				}},
				"finish_reason": "tool_calls",
			}},
		})
		terminalBody := append([]byte("data: "), terminalPayload...)
		terminalBody = append(terminalBody, '\n', '\n')
		terminalResponse := invokeStreamBody(t, formatOpenAI, requestBody, 1, terminalBody)
		terminalDelivered := deliveredStreamBody(terminalResponse, terminalBody)

		frames := parseSemanticSSEFrames(terminalDelivered)
		if len(frames) != 2 {
			t.Fatalf("terminal emitted %d frames, want prior-channel synthetic then terminal", len(frames))
		}
		terminalArguments := openAIChatToolArguments(t, terminalDelivered)
		if got := terminalArguments["3:0"]; got != partial {
			t.Fatalf("prior channel terminal flush = %q, want %q", got, partial)
		}
		if got := terminalArguments["3:1"]; got != firstCurrent {
			t.Fatalf("first same-frame tool argument = %q, want %q", got, firstCurrent)
		}
		if got := terminalArguments["3:2"]; got != secondCurrent {
			t.Fatalf("second same-frame tool argument = %q, want %q", got, secondCurrent)
		}

		allArguments := openAIChatToolArguments(t, append(priorDelivered, terminalDelivered...))
		if got := allArguments["3:0"]; got != priorFragment {
			t.Fatalf("prior channel source order = %q, want %q", got, priorFragment)
		}
	})
}

func TestOpenAIChatDoneFlushesAllToolArguments(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "openai-done-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	partial := token[:len(token)/2]

	var delivered []byte
	for index, channel := range []struct{ choice, tool int }{{choice: 0, tool: 1}, {choice: 2, tool: 4}} {
		body := openAIChatToolArgumentSSEBody(t, channel.choice, channel.tool, `{"value":"`+partial, nil)
		response := invokeStreamBody(t, formatOpenAI, requestBody, index, body)
		delivered = append(delivered, deliveredStreamBody(response, body)...)
	}
	doneBody := []byte("data: [DONE]\n\n")
	done := invokeStreamBody(t, formatOpenAI, requestBody, 2, doneBody)
	doneDelivered := deliveredStreamBody(done, doneBody)
	delivered = append(delivered, doneDelivered...)
	if !bytes.HasSuffix(doneDelivered, doneBody) {
		t.Fatalf("[DONE] sentinel was not preserved at the end: %q", doneDelivered)
	}
	flushed := openAIChatToolArguments(t, doneDelivered)
	for _, channel := range []string{"0:1", "2:4"} {
		if got := flushed[channel]; got != partial {
			t.Fatalf("[DONE] event flush for channel %s = %q, want %q", channel, got, partial)
		}
	}

	arguments := openAIChatToolArguments(t, delivered)
	for _, channel := range []string{"0:1", "2:4"} {
		if got, want := arguments[channel], `{"value":"`+partial; got != want {
			t.Fatalf("[DONE] flush for channel %s = %q, want %q", channel, got, want)
		}
	}
	streamCarry.mu.Lock()
	defer streamCarry.mu.Unlock()
	if entry := streamCarry.entries[streamKey(requestBody)]; entry != nil && len(entry.arguments) != 0 {
		t.Fatalf("[DONE] retained argument state: %#v", entry.arguments)
	}
}

func TestOpenAIChatToolArgumentRejectsInvalidIndices(t *testing.T) {
	label := "REDACTED"
	token := makeToken(label, "invalid-tool-index")
	partial := `{"value":"` + token[:len(token)/2]
	for _, tc := range []struct {
		name  string
		index any
		omit  bool
	}{
		{name: "missing", omit: true},
		{name: "negative", index: -1},
		{name: "non-integer", index: 0.5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := "invalid-openai-tool-index-" + tc.name
			streamCarry.reset(key)
			tool := map[string]any{"function": map[string]any{"arguments": partial}}
			if !tc.omit {
				tool["index"] = tc.index
			}
			payload := mustJSONMarshal(t, map[string]any{
				"object": "chat.completion.chunk",
				"choices": []any{map[string]any{
					"index": 0, "delta": map[string]any{"tool_calls": []any{tool}}, "finish_reason": nil,
				}},
			})
			body := append([]byte("data: "), payload...)
			body = append(body, '\n', '\n')
			out, handled := restoreSemanticStream(key, body, tokenPattern(label), []string{label}, map[string]struct{}{token: {}}, newVault(1, time.Hour), "text/event-stream", formatOpenAI)
			if !handled || !bytes.Equal(out, body) {
				t.Fatalf("invalid tool index changed fragment: handled=%v out=%q want=%q", handled, out, body)
			}
			streamCarry.mu.Lock()
			entry := streamCarry.entries[key]
			if entry != nil && len(entry.arguments) != 0 {
				streamCarry.mu.Unlock()
				t.Fatalf("invalid tool index retained state: %#v", entry.arguments)
			}
			streamCarry.mu.Unlock()
		})
	}
}

func TestOpenAIChatToolArgumentIdentityIgnoresLateID(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "openai-late-tool-id"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2

	firstBody := openAIChatToolArgumentSSEBody(t, 0, 2, `{"value":"`+token[:split], nil)
	first := invokeStreamBody(t, formatOpenAI, requestBody, 0, firstBody)
	secondPayload := mustJSONMarshal(t, map[string]any{
		"object": "chat.completion.chunk",
		"choices": []any{map[string]any{
			"index": 0,
			"delta": map[string]any{"tool_calls": []any{map[string]any{
				"index": 2, "id": "call_late", "function": map[string]any{"arguments": token[split:] + `"}`},
			}}},
			"finish_reason": nil,
		}},
	})
	secondBody := append([]byte("data: "), secondPayload...)
	secondBody = append(secondBody, '\n', '\n')
	second := invokeStreamBody(t, formatOpenAI, requestBody, 1, secondBody)
	delivered := append(deliveredStreamBody(first, firstBody), deliveredStreamBody(second, secondBody)...)
	argument := openAIChatToolArguments(t, delivered)["0:2"]
	var decoded map[string]string
	if err := json.Unmarshal([]byte(argument), &decoded); err != nil || decoded["value"] != secret {
		t.Fatalf("late tool ID changed channel identity: argument=%q decoded=%#v err=%v", argument, decoded, err)
	}
}

func TestOpenAIChatToolArgumentSpecialCharactersRemainValid(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "quote=\" slash=\\ line=\n tab=\t control=\x01 unicode=世界 html=<>&"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2

	firstBody := openAIChatToolArgumentSSEBody(t, 0, 0, `{"value":"`+token[:split], nil)
	first := invokeStreamBody(t, formatOpenAI, requestBody, 0, firstBody)
	secondBody := openAIChatToolArgumentSSEBody(t, 0, 0, token[split:]+`"}`, nil)
	second := invokeStreamBody(t, formatOpenAI, requestBody, 1, secondBody)
	delivered := append(deliveredStreamBody(first, firstBody), deliveredStreamBody(second, secondBody)...)
	argument := openAIChatToolArguments(t, delivered)["0:0"]
	var decoded map[string]string
	if err := json.Unmarshal([]byte(argument), &decoded); err != nil {
		t.Fatalf("special-character arguments are invalid JSON %q: %v", argument, err)
	}
	if got := decoded["value"]; got != secret {
		t.Fatalf("special-character value = %q, want %q", got, secret)
	}
}

func TestOpenAIResponsesFunctionArgumentDeltaRestoresSplitWithEncodedItemID(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-function-argument-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)
	itemID := "call:with/slash/世界"
	split := len(token) / 2

	firstPayload := responsesFunctionArgumentDelta(t, 3, itemID, `{"value":"`+token[:split])
	firstBody := responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", firstPayload)
	first := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, firstBody)
	firstDelivered := deliveredStreamBody(first, firstBody)
	if got, want := openAIResponsesFunctionArgumentDeltas(t, firstDelivered)["3:"+itemID], `{"value":"`; got != want {
		t.Fatalf("first function-argument delta = %q, want %q", got, want)
	}

	channel := "argument:openai-response:output:3:item:" + base64.RawURLEncoding.EncodeToString([]byte(itemID))
	streamCarry.mu.Lock()
	entry := streamCarry.entries[streamKey(requestBody)]
	_, retained := entry.arguments[channel]
	streamCarry.mu.Unlock()
	if !retained {
		t.Fatalf("encoded Responses argument channel %q was not retained", channel)
	}

	secondPayload := responsesFunctionArgumentDelta(t, 3, itemID, token[split:]+`"}`)
	secondBody := responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", secondPayload)
	second := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, secondBody)
	delivered := append(firstDelivered, deliveredStreamBody(second, secondBody)...)
	argument := openAIResponsesFunctionArgumentDeltas(t, delivered)["3:"+itemID]
	var decoded map[string]string
	if err := json.Unmarshal([]byte(argument), &decoded); err != nil {
		t.Fatalf("split Responses arguments are invalid JSON %q: %v", argument, err)
	}
	if got := decoded["value"]; got != secret {
		t.Fatalf("split Responses argument value = %q, want %q", got, secret)
	}
}

func TestOpenAIResponsesFunctionArgumentDoneFlushesAndRestoresAggregate(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-dedicated-done-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)
	itemID := "call_done"
	partial := token[:len(token)/2]

	firstPayload := responsesFunctionArgumentDelta(t, 0, itemID, `{"value":"`+partial)
	firstBody := responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", firstPayload)
	first := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, firstBody)
	if got := openAIResponsesFunctionArgumentDeltas(t, deliveredStreamBody(first, firstBody))["0:"+itemID]; got != `{"value":"` {
		t.Fatalf("pending suffix reached client before done: %q", got)
	}

	doneArguments := `{"aggregate":"` + token + `"}`
	donePayload := responsesFunctionArgumentDone(t, 0, itemID, doneArguments)
	doneBody := responsesFunctionArgumentSSEBody("response.function_call_arguments.done", donePayload)
	done := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, doneBody)
	doneDelivered := deliveredStreamBody(done, doneBody)
	if got := openAIResponsesFunctionArgumentDeltas(t, doneDelivered)["0:"+itemID]; got != partial {
		t.Fatalf("dedicated done flush = %q, want %q", got, partial)
	}
	doc := findOpenAIResponsesEvent(t, doneDelivered, "response.function_call_arguments.done")
	if got, want := doc["arguments"], `{"aggregate":"`+secret+`"}`; got != want {
		t.Fatalf("dedicated done aggregate = %#v, want %q", got, want)
	}
	if deltaAt, doneAt := bytes.Index(doneDelivered, []byte(`"response.function_call_arguments.delta"`)), bytes.Index(doneDelivered, []byte(`"response.function_call_arguments.done"`)); deltaAt < 0 || doneAt < 0 || deltaAt >= doneAt {
		t.Fatalf("dedicated done output order is not delta-before-done: %q", doneDelivered)
	}
}

func TestOpenAIResponsesFunctionArgumentAggregateDoesNotDuplicateClosedDelta(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-later-aggregate-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)
	itemID := "call_later_aggregate"
	partial := token[:len(token)/2]

	deltaBody := responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", responsesFunctionArgumentDelta(t, 2, itemID, `{"value":"`+partial))
	delta := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, deltaBody)
	_ = deliveredStreamBody(delta, deltaBody)
	doneBody := responsesFunctionArgumentSSEBody("response.function_call_arguments.done", responsesFunctionArgumentDone(t, 2, itemID, `{"value":"`+token+`"}`))
	done := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, doneBody)
	if got := openAIResponsesFunctionArgumentDeltas(t, deliveredStreamBody(done, doneBody))["2:"+itemID]; got != partial {
		t.Fatalf("dedicated done flush = %q, want %q", got, partial)
	}

	aggregatePayload := mustJSONMarshal(t, map[string]any{
		"type":         "response.output_item.done",
		"output_index": 2,
		"item": map[string]any{
			"type": "function_call", "id": itemID, "arguments": `{"value":"` + token + `"}`,
		},
	})
	aggregateBody := responsesFunctionArgumentSSEBody("response.output_item.done", aggregatePayload)
	aggregate := invokeStreamBody(t, formatOpenAIResponse, requestBody, 2, aggregateBody)
	aggregateDelivered := deliveredStreamBody(aggregate, aggregateBody)
	if got := openAIResponsesFunctionArgumentDeltas(t, aggregateDelivered)["2:"+itemID]; got != "" {
		t.Fatalf("later aggregate emitted duplicate delta %q", got)
	}
	doc := findOpenAIResponsesEvent(t, aggregateDelivered, "response.output_item.done")
	item := doc["item"].(map[string]any)
	if got, want := item["arguments"], `{"value":"`+secret+`"}`; got != want {
		t.Fatalf("later output-item aggregate = %#v, want %q", got, want)
	}
}

func TestOpenAIResponsesFunctionArgumentAggregateFlushesWithoutDedicatedDone(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-aggregate-flush-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)
	itemID := "call_aggregate_flush"
	partial := token[:len(token)/2]

	deltaBody := responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", responsesFunctionArgumentDelta(t, 5, itemID, `{"value":"`+partial))
	delta := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, deltaBody)
	_ = deliveredStreamBody(delta, deltaBody)
	aggregatePayload := mustJSONMarshal(t, map[string]any{
		"type":            "response.output_item.done",
		"output_index":    5,
		"sequence_number": 42,
		"item": map[string]any{
			"type": "function_call", "id": itemID, "arguments": `{"value":"` + token + `"}`,
		},
	})
	aggregateBody := responsesFunctionArgumentSSEBody("response.output_item.done", aggregatePayload)
	aggregate := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, aggregateBody)
	aggregateDelivered := deliveredStreamBody(aggregate, aggregateBody)
	deltas := openAIResponsesFunctionArgumentDeltas(t, aggregateDelivered)
	if got := deltas["5:"+itemID]; got != partial {
		t.Fatalf("output-item done flush = %q, want %q", got, partial)
	}
	for _, doc := range openAIResponsesEventDocs(t, aggregateDelivered) {
		if doc["type"] == "response.function_call_arguments.delta" && doc["sequence_number"] != json.Number("42") {
			t.Fatalf("synthetic sequence number = %#v, want 42", doc["sequence_number"])
		}
	}
}

func TestOpenAIResponsesCompletedFlushesFunctionArguments(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-completed-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)
	partial := token[:len(token)/2]
	channels := []struct {
		output int
		item   string
	}{{output: 0, item: "call_a"}, {output: 9, item: "call:b/世界"}}

	for i, channel := range channels {
		body := responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", responsesFunctionArgumentDelta(t, channel.output, channel.item, `{"value":"`+partial))
		response := invokeStreamBody(t, formatOpenAIResponse, requestBody, i, body)
		_ = deliveredStreamBody(response, body)
	}
	completedPayload := mustJSONMarshal(t, map[string]any{"type": "response.completed", "sequence_number": 77})
	completedBody := responsesFunctionArgumentSSEBody("response.completed", completedPayload)
	completed := invokeStreamBody(t, formatOpenAIResponse, requestBody, len(channels), completedBody)
	completedDelivered := deliveredStreamBody(completed, completedBody)
	deltas := openAIResponsesFunctionArgumentDeltas(t, completedDelivered)
	for _, channel := range channels {
		key := fmt.Sprintf("%d:%s", channel.output, channel.item)
		if got := deltas[key]; got != partial {
			t.Fatalf("response.completed flush for %s = %q, want %q", key, got, partial)
		}
	}
}

func TestOpenAIResponsesCompletedFunctionCallArgumentsUseAtomicRestoration(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "quote=\" slash=\\ line=\n tab=\t control=\x01 unicode=世界 html=<>&"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)

	completedBody := func(arguments string) []byte {
		payload := mustJSONMarshal(t, map[string]any{
			"type":            "response.completed",
			"sequence_number": 77,
			"response": map[string]any{
				"id": "resp_cli_proxy", "object": "response", "created_at": 1,
				"status": "completed", "background": false, "error": nil,
				"instructions": token,
				"output": []any{
					map[string]any{
						"id": "fc_call_completed", "type": "function_call", "status": "completed",
						"arguments": arguments, "call_id": "call_completed", "name": "read",
					},
					map[string]any{
						"id": "ctc_custom", "type": "custom_tool_call", "status": "completed",
						"input": token, "call_id": "call_custom", "name": "shell",
					},
				},
			},
		})
		return responsesFunctionArgumentSSEBody("response.completed", payload)
	}

	t.Run("CLIProxyAPI payload restores aggregate after synthetic flush", func(t *testing.T) {
		resetStreamCarry(requestBody)
		partial := token[:len(token)/2]
		deltaBody := responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", responsesFunctionArgumentDelta(t, 0, "call_completed", `{"value":"`+partial))
		delta := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, deltaBody)
		_ = deliveredStreamBody(delta, deltaBody)

		body := completedBody(`{"value":"` + token + `"}`)
		response := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, body)
		delivered := deliveredStreamBody(response, body)
		docs := openAIResponsesEventDocs(t, delivered)
		if len(docs) != 2 || docs[0]["type"] != "response.function_call_arguments.delta" || docs[1]["type"] != "response.completed" {
			t.Fatalf("completed output order = %#v, want synthetic delta then completed", docs)
		}
		if got := docs[0]["delta"]; got != partial {
			t.Fatalf("completed synthetic tail = %#v, want %q", got, partial)
		}

		completed := docs[1]["response"].(map[string]any)
		output := completed["output"].([]any)
		functionCall := output[0].(map[string]any)
		arguments := functionCall["arguments"].(string)
		var decoded map[string]string
		if err := json.Unmarshal([]byte(arguments), &decoded); err != nil {
			t.Fatalf("completed function-call arguments are invalid JSON %q: %v", arguments, err)
		}
		if got := decoded["value"]; got != secret {
			t.Fatalf("completed function-call argument = %q, want %q", got, secret)
		}
		if got := output[1].(map[string]any)["input"]; got != secret {
			t.Fatalf("completed custom-tool input = %#v, want generic restoration %q", got, secret)
		}
		if got := completed["instructions"]; got != secret {
			t.Fatalf("completed ordinary field = %#v, want %q", got, secret)
		}
	})

	t.Run("malformed aggregate remains unchanged", func(t *testing.T) {
		resetStreamCarry(requestBody)
		malformed := `{"value":"` + token
		body := completedBody(malformed)
		response := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, body)
		delivered := deliveredStreamBody(response, body)
		doc := findOpenAIResponsesEvent(t, delivered, "response.completed")
		completed := doc["response"].(map[string]any)
		functionCall := completed["output"].([]any)[0].(map[string]any)
		if got := functionCall["arguments"]; got != malformed {
			t.Fatalf("malformed completed aggregate = %#v, want %q", got, malformed)
		}
		if got := completed["instructions"]; got != secret {
			t.Fatalf("ordinary completed field beside malformed aggregate = %#v, want %q", got, secret)
		}
	})
}

func TestOpenAIResponsesFunctionArgumentRejectsInvalidIdentity(t *testing.T) {
	label := "REDACTED"
	token := makeToken(label, "invalid-responses-identity")
	fragment := `{"value":"` + token[:len(token)/2]
	for _, tc := range []struct {
		name        string
		outputIndex any
		omitOutput  bool
		itemID      any
		omitItem    bool
	}{
		{name: "missing output", omitOutput: true, itemID: "call"},
		{name: "negative output", outputIndex: -1, itemID: "call"},
		{name: "fractional output", outputIndex: 0.5, itemID: "call"},
		{name: "missing item", outputIndex: 0, omitItem: true},
		{name: "empty item", outputIndex: 0, itemID: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := "invalid-responses-identity-" + tc.name
			streamCarry.reset(key)
			doc := map[string]any{
				"type":  "response.function_call_arguments.delta",
				"delta": fragment,
			}
			if !tc.omitOutput {
				doc["output_index"] = tc.outputIndex
			}
			if !tc.omitItem {
				doc["item_id"] = tc.itemID
			}
			body := responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", mustJSONMarshal(t, doc))
			out, handled := restoreSemanticStream(key, body, tokenPattern(label), []string{label}, map[string]struct{}{token: {}}, newVault(1, time.Hour), "text/event-stream", formatOpenAIResponse)
			if handled && !bytes.Equal(out, body) {
				t.Fatalf("invalid Responses identity changed: handled=%v out=%q want=%q", handled, out, body)
			}
			streamCarry.mu.Lock()
			entry := streamCarry.entries[key]
			if entry != nil && len(entry.arguments) != 0 {
				streamCarry.mu.Unlock()
				t.Fatalf("invalid Responses identity retained state: %#v", entry.arguments)
			}
			streamCarry.mu.Unlock()
		})
	}
}

func TestOpenAIResponsesFunctionArgumentIndependentFromOutputText(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-independent-channels"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2

	textFirstBody := responsesOutputTextDeltaBody(t, token[:split])
	textFirst := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, textFirstBody)
	if got := openAIResponsesStreamText(t, deliveredStreamBody(textFirst, textFirstBody)); got != "" {
		t.Fatalf("output-text prefix reached client: %q", got)
	}
	argumentFirstBody := responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", responsesFunctionArgumentDelta(t, 0, "msg_privacy", `{"value":"`+token[:split]))
	argumentFirst := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, argumentFirstBody)
	if got := openAIResponsesFunctionArgumentDeltas(t, deliveredStreamBody(argumentFirst, argumentFirstBody))["0:msg_privacy"]; got != `{"value":"` {
		t.Fatalf("function-argument prefix output = %q", got)
	}
	argumentSecondBody := responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", responsesFunctionArgumentDelta(t, 0, "msg_privacy", token[split:]+`"}`))
	argumentSecond := invokeStreamBody(t, formatOpenAIResponse, requestBody, 2, argumentSecondBody)
	argument := openAIResponsesFunctionArgumentDeltas(t, append(deliveredStreamBody(argumentFirst, argumentFirstBody), deliveredStreamBody(argumentSecond, argumentSecondBody)...))["0:msg_privacy"]
	var decoded map[string]string
	if err := json.Unmarshal([]byte(argument), &decoded); err != nil || decoded["value"] != secret {
		t.Fatalf("independent function arguments = %q decoded=%#v err=%v", argument, decoded, err)
	}
	textSecondBody := responsesOutputTextDeltaBody(t, token[split:])
	textSecond := invokeStreamBody(t, formatOpenAIResponse, requestBody, 3, textSecondBody)
	if got := openAIResponsesStreamText(t, deliveredStreamBody(textSecond, textSecondBody)); got != secret {
		t.Fatalf("function argument consumed output-text pending state: %q", got)
	}
}

func TestOpenAIResponsesCustomToolArgumentsKeepGenericBehavior(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-custom-tool-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)

	for index, tc := range []struct {
		name      string
		eventType string
		doc       map[string]any
		value     func(map[string]any) string
	}{
		{
			name: "custom input done", eventType: "response.custom_tool_call_input.done",
			doc:   map[string]any{"type": "response.custom_tool_call_input.done", "output_index": 0, "item_id": "custom", "input": token},
			value: func(doc map[string]any) string { return doc["input"].(string) },
		},
		{
			name: "custom output item", eventType: "response.output_item.done",
			doc: map[string]any{
				"type": "response.output_item.done", "output_index": 0,
				"item": map[string]any{"type": "custom_tool_call", "id": "custom", "input": token},
			},
			value: func(doc map[string]any) string { return doc["item"].(map[string]any)["input"].(string) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := responsesFunctionArgumentSSEBody(tc.eventType, mustJSONMarshal(t, tc.doc))
			response := invokeStreamBody(t, formatOpenAIResponse, requestBody, index, body)
			delivered := deliveredStreamBody(response, body)
			doc := findOpenAIResponsesEvent(t, delivered, tc.eventType)
			if got := tc.value(doc); got != secret {
				t.Fatalf("custom tool generic restoration = %q, want %q", got, secret)
			}
		})
	}
	streamCarry.mu.Lock()
	defer streamCarry.mu.Unlock()
	if entry := streamCarry.entries[streamKey(requestBody)]; entry != nil && len(entry.arguments) != 0 {
		t.Fatalf("custom tool events retained argument state: %#v", entry.arguments)
	}
}

func TestSplitSSETokenRestoresWithJSONEscaping(t *testing.T) {
	setSharedVault(newVault(100, time.Hour))
	label := "REDACTED"
	tokenRe := restoreTokenPattern()
	secret := "line1\"quote\\slash\nline2"
	token := makeToken(label, secret)
	getSharedVault().Put(token, secret)
	allowed := collectTokens([]byte(token), tokenRe, getSharedVault())
	key := "split-sse-escaping"
	streamCarry.reset(key)

	half := len(token) / 2
	first := []byte(`data: {"delta":"` + token[:half])
	second := []byte(token[half:] + `"}` + "\n\n")
	out1, drop1 := detokenizeStreamChunk(key, first, tokenRe, []string{label}, allowed, getSharedVault(), true)
	if !drop1 || len(out1) != 0 {
		t.Fatalf("incomplete SSE frame must be withheld: drop=%v out=%q", drop1, out1)
	}
	out2, drop2 := detokenizeStreamChunk(key, second, tokenRe, []string{label}, allowed, getSharedVault(), true)
	if drop2 {
		t.Fatal("completed SSE frame must be emitted")
	}
	line := strings.TrimSpace(strings.TrimPrefix(string(out2), "data:"))
	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("restored split SSE payload is invalid JSON: %v (%q)", err, line)
	}
	if payload["delta"] != secret {
		t.Fatalf("split SSE secret not restored exactly: %q", payload["delta"])
	}
}

func TestOpenAICompletionStreamRestoresTokenSplitAcrossContentDeltas(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "sk-openai-stream-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"role":"user","content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)

	split := len(token) / 2
	first, firstBody := invokeOpenAIContentDelta(t, formatOpenAI, requestBody, 0, token[:split])
	if got := openAIStreamContent(t, deliveredStreamBody(first, firstBody)); strings.Contains(got, token[:split]) {
		t.Fatalf("partial token delta was sent to the client: %q", got)
	}
	second, _ := invokeOpenAIContentDelta(t, formatOpenAI, requestBody, 1, token[split:])
	if second.DropChunk || !bytes.Contains(second.Body, []byte(secret)) || bytes.Contains(second.Body, []byte(token)) {
		t.Fatalf("split content deltas were not restored: %+v", second)
	}
}

func TestOpenAICompletionBareJSONStreamRestoresTokenSplitAcrossContentDeltas(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "sk-openai-bare-json-stream-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"role":"user","content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)

	split := len(token) / 2
	first, firstBody := invokeOpenAIBareContentDelta(t, requestBody, 0, token[:split])
	if got := openAIBareStreamContent(t, deliveredStreamBody(first, firstBody)); strings.Contains(got, token[:split]) {
		t.Fatalf("partial token delta was sent to the client: %q", got)
	}
	second, secondBody := invokeOpenAIBareContentDelta(t, requestBody, 1, token[split:])
	if got := openAIBareStreamContent(t, deliveredStreamBody(second, secondBody)); got != secret {
		t.Fatalf("split bare JSON content deltas were not restored: %q", got)
	}
}

func TestOpenAIResponsesStreamRestoresTokenSplitAcrossOutputTextDeltas(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-stream-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":[{"role":"user","content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2

	firstBody := responsesOutputTextDeltaBody(t, token[:split])
	first := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, firstBody)
	if bytes.Contains(deliveredStreamBody(first, firstBody), []byte(token[:split])) {
		t.Fatal("partial Responses token reached the client")
	}
	secondBody := responsesOutputTextDeltaBody(t, token[split:])
	second := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, secondBody)
	if delivered := deliveredStreamBody(second, secondBody); !bytes.Contains(delivered, []byte(secret)) || bytes.Contains(delivered, []byte(token)) {
		t.Fatalf("Responses split token was not restored: %q", delivered)
	}
}

func TestOpenAIResponsesAtomicSSEChunksRestoreSplitToken(t *testing.T) {
	for _, tt := range []struct {
		name     string
		dataOnly bool
	}{
		{name: "event-and-data"},
		{name: "data-only", dataOnly: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			callRegister(t, pluginabi.MethodPluginRegister, "")
			st := activeSnapshot()
			secret := "responses-atomic-stream-secret-" + tt.name
			token := makeToken(st.label, secret)
			st.vault.Put(token, secret)
			requestBody := []byte(`{"input":"` + token + `"}`)
			resetStreamCarry(requestBody)
			split := len(token) / 2

			atomicBody := func(delta string) []byte {
				body := bytes.TrimSuffix(responsesOutputTextDeltaBody(t, delta), []byte("\n\n"))
				if !tt.dataOnly {
					return body
				}
				dataStart := bytes.Index(body, []byte("data:"))
				if dataStart < 0 {
					t.Fatal("Responses fixture has no data field")
				}
				return body[dataStart:]
			}

			firstBody := atomicBody(token[:split])
			first := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, firstBody)
			if first.DropChunk {
				t.Fatal("complete atomic Responses event was treated as unfinished SSE")
			}
			firstDelivered := deliveredStreamBody(first, firstBody)
			if got := openAIResponsesStreamText(t, firstDelivered); got != "" {
				t.Fatalf("partial Responses token reached the client: %q", got)
			}
			if bytes.HasSuffix(firstDelivered, []byte("\n\n")) {
				t.Fatal("plugin added the host-owned SSE separator")
			}

			secondBody := atomicBody(token[split:])
			second := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, secondBody)
			if second.DropChunk {
				t.Fatal("completed atomic Responses token was not emitted")
			}
			secondDelivered := deliveredStreamBody(second, secondBody)
			if got := openAIResponsesStreamText(t, secondDelivered); got != secret {
				t.Fatalf("atomic Responses deltas did not restore the token: %q", got)
			}
			if bytes.HasSuffix(secondDelivered, []byte("\n\n")) {
				t.Fatal("plugin added the host-owned SSE separator")
			}
		})
	}
}

func TestOpenAIResponsesSparseOutputTextDeltasShareChannel(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-sparse-stream-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2

	firstBody := responsesSSEBody(t, "response.output_text.delta", map[string]any{
		"type":          "response.output_text.delta",
		"output_index":  0,
		"content_index": 0,
		"delta":         token[:split],
	}, "\n")
	first := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, firstBody)
	if got := openAIResponsesStreamText(t, deliveredStreamBody(first, firstBody)); got != "" {
		t.Fatalf("sparse Responses prefix reached the client: %q", got)
	}

	secondBody := responsesSSEBody(t, "response.output_text.delta", map[string]any{
		"type":          "response.output_text.delta",
		"output_index":  0,
		"content_index": 0,
		"delta":         token[split:],
	}, "\n")
	second := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, secondBody)
	if got := openAIResponsesStreamText(t, deliveredStreamBody(second, secondBody)); got != secret {
		t.Fatalf("sparse Responses deltas did not share a channel: %q", got)
	}
}

func TestOpenAIResponsesNonemptyItemIDsRemainIsolated(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-item-isolation-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2
	makeDelta := func(itemID, delta string) []byte {
		return responsesSSEBody(t, "response.output_text.delta", map[string]any{
			"type":          "response.output_text.delta",
			"item_id":       itemID,
			"output_index":  0,
			"content_index": 0,
			"delta":         delta,
		}, "\n")
	}

	firstBody := makeDelta("msg_a", token[:split])
	first := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, firstBody)
	if got := openAIResponsesStreamText(t, deliveredStreamBody(first, firstBody)); got != "" {
		t.Fatalf("first item prefix reached the client: %q", got)
	}
	otherBody := makeDelta("msg_b", token[split:])
	other := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, otherBody)
	if got := openAIResponsesStreamText(t, deliveredStreamBody(other, otherBody)); got != token[split:] {
		t.Fatalf("different item ID consumed pending text: %q", got)
	}
	completionBody := makeDelta("msg_a", token[split:])
	completion := invokeStreamBody(t, formatOpenAIResponse, requestBody, 2, completionBody)
	if got := openAIResponsesStreamText(t, deliveredStreamBody(completion, completionBody)); got != secret {
		t.Fatalf("original item channel did not restore independently: %q", got)
	}
}

func TestClaudeStreamRestoresTokenSplitAcrossTextDeltas(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "claude-stream-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"role":"user","content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2

	firstBody := claudeTextDeltaBody(t, 0, token[:split])
	first := invokeStreamBody(t, formatClaude, requestBody, 0, firstBody)
	if bytes.Contains(deliveredStreamBody(first, firstBody), []byte(token[:split])) {
		t.Fatal("partial Claude token reached the client")
	}
	secondBody := claudeTextDeltaBody(t, 0, token[split:])
	second := invokeStreamBody(t, formatClaude, requestBody, 1, secondBody)
	if delivered := deliveredStreamBody(second, secondBody); !bytes.Contains(delivered, []byte(secret)) || bytes.Contains(delivered, []byte(token)) {
		t.Fatalf("Claude split token was not restored: %q", delivered)
	}
}

func TestGeminiBareJSONStreamRestoresTokenSplitAcrossTextParts(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "gemini-bare-json-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"contents":[{"parts":[{"text":"` + token + `"}]}]}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2

	firstBody := geminiBody(t, token[:split])
	first := invokeStreamBody(t, formatGemini, requestBody, 0, firstBody)
	if got := geminiStreamText(t, deliveredStreamBody(first, firstBody)); strings.Contains(got, token[:split]) {
		t.Fatalf("partial Gemini token reached the client: %q", got)
	}
	secondBody := geminiBody(t, token[split:])
	second := invokeStreamBody(t, formatGemini, requestBody, 1, secondBody)
	if delivered := deliveredStreamBody(second, secondBody); !bytes.Contains(delivered, []byte(secret)) || bytes.Contains(delivered, []byte(token)) {
		t.Fatalf("Gemini bare-JSON split token was not restored: %q", delivered)
	}
}

func TestGeminiSSEStreamRestoresTokenSplitAcrossTextParts(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "gemini-sse-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"contents":[{"parts":[{"text":"` + token + `"}]}]}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2

	firstBody := geminiSSEBody(t, token[:split])
	first := invokeStreamBody(t, formatGemini, requestBody, 0, firstBody)
	if got := geminiStreamText(t, deliveredStreamBody(first, firstBody)); strings.Contains(got, token[:split]) {
		t.Fatalf("partial Gemini SSE token reached the client: %q", got)
	}
	secondBody := geminiSSEBody(t, token[split:])
	second := invokeStreamBody(t, formatGemini, requestBody, 1, secondBody)
	if delivered := deliveredStreamBody(second, secondBody); !bytes.Contains(delivered, []byte(secret)) || bytes.Contains(delivered, []byte(token)) {
		t.Fatalf("Gemini SSE split token was not restored: %q", delivered)
	}
}

func TestGeminiBareJSONStreamRestoresCompleteToken(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "gemini complete visible secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"contents":[{"parts":[{"text":"` + token + `"}]}]}`)
	resetStreamCarry(requestBody)

	body := geminiBody(t, token)
	response := invokeStreamBody(t, formatGemini, requestBody, 0, body)
	var doc struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(deliveredStreamBody(response, body), &doc); err != nil {
		t.Fatalf("unmarshal restored Gemini body: %v", err)
	}
	if len(doc.Candidates) != 1 || len(doc.Candidates[0].Content.Parts) != 1 || doc.Candidates[0].Content.Parts[0].Text != secret {
		t.Fatalf("complete Gemini token was not restored: %#v", doc)
	}
}

func TestGeminiSingleEventRestoresGenericFieldsButNotThoughtText(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	visibleSecret := "gemini-visible-once-secret"
	visibleInnerToken := makeToken(st.label, visibleSecret)
	visibleOuterToken := makeToken(st.label, visibleInnerToken)
	argumentSecret := "gemini-function-argument-secret"
	argumentToken := makeToken(st.label, argumentSecret)
	thoughtSecret := "gemini-thought-secret"
	thoughtToken := makeToken(st.label, thoughtSecret)
	st.vault.Put(visibleInnerToken, visibleSecret)
	st.vault.Put(visibleOuterToken, visibleInnerToken)
	st.vault.Put(argumentToken, argumentSecret)
	st.vault.Put(thoughtToken, thoughtSecret)
	requestBody := mustJSONMarshal(t, map[string]any{
		"contents": []any{map[string]any{"parts": []any{map[string]any{
			"text": visibleOuterToken + " " + visibleInnerToken + " " + argumentToken + " " + thoughtToken,
		}}}},
	})
	resetStreamCarry(requestBody)
	body := geminiCandidatesBody(t, []any{map[string]any{
		"index": 0,
		"content": map[string]any{"parts": []any{
			map[string]any{"text": visibleOuterToken},
			map[string]any{"functionCall": map[string]any{"name": "lookup", "args": map[string]any{"value": argumentToken}}},
			map[string]any{"thought": true, "text": thoughtToken},
		}},
	}})

	response := invokeStreamBody(t, formatGemini, requestBody, 0, body)
	delivered := deliveredStreamBody(response, body)
	var doc struct {
		Candidates []struct {
			Content struct {
				Parts []map[string]any `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(delivered, &doc); err != nil {
		t.Fatalf("unmarshal Gemini generic-restoration body: %v", err)
	}
	parts := doc.Candidates[0].Content.Parts
	if got := parts[0]["text"]; got != visibleInnerToken {
		t.Fatalf("Gemini visible text was not restored exactly once: got %#v want %q", got, visibleInnerToken)
	}
	functionCall := parts[1]["functionCall"].(map[string]any)
	args := functionCall["args"].(map[string]any)
	if got := args["value"]; got != argumentSecret {
		t.Fatalf("complete function argument token was not generically restored: %#v", got)
	}
	if got := parts[2]["text"]; got != thoughtToken {
		t.Fatalf("thought text was restored unexpectedly: got %#v want %q", got, thoughtToken)
	}
}

func TestGeminiFunctionArgumentUsesGenericWalkerWithoutArgumentState(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "gemini-structured-function-argument"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"contents":[{"parts":[{"text":"` + token + `"}]}]}`)
	resetStreamCarry(requestBody)
	body := geminiCandidatesBody(t, []any{map[string]any{
		"index": 0,
		"content": map[string]any{"parts": []any{map[string]any{
			"functionCall": map[string]any{"name": "lookup", "args": map[string]any{"value": token}},
		}}},
	}})

	response := invokeStreamBody(t, formatGemini, requestBody, 0, body)
	delivered := deliveredStreamBody(response, body)
	doc, ok := decodeOneJSON(delivered)
	if !ok {
		t.Fatalf("invalid Gemini response: %q", delivered)
	}
	root := doc.(map[string]any)
	candidate := root["candidates"].([]any)[0].(map[string]any)
	content := candidate["content"].(map[string]any)
	part := content["parts"].([]any)[0].(map[string]any)
	functionCall := part["functionCall"].(map[string]any)
	args := functionCall["args"].(map[string]any)
	if got := args["value"]; got != secret {
		t.Fatalf("Gemini functionCall.args generic restoration = %#v, want %q", got, secret)
	}

	streamCarry.mu.Lock()
	defer streamCarry.mu.Unlock()
	if entry := streamCarry.entries[streamKey(requestBody)]; entry != nil && entry.arguments != nil {
		t.Fatalf("Gemini structured arguments created argument state: %#v", entry.arguments)
	}
}

func TestGeminiStreamFlushesPendingPartsInIndexOrderWithoutExistingContent(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	firstToken := makeToken(st.label, "gemini-terminal-first")
	secondToken := makeToken(st.label, "gemini-terminal-second")
	st.vault.Put(firstToken, "gemini-terminal-first")
	st.vault.Put(secondToken, "gemini-terminal-second")
	requestBody := []byte(`{"contents":[{"parts":[{"text":"` + firstToken + ` ` + secondToken + `"}]}]}`)
	resetStreamCarry(requestBody)
	firstPartial := firstToken[:len(firstToken)/2]
	secondPartial := secondToken[:len(secondToken)/2]

	firstBody := geminiCandidatesBody(t, []any{map[string]any{
		"index": 4,
		"content": map[string]any{
			"role": "model",
			"parts": []any{
				map[string]any{"text": firstPartial},
				map[string]any{"text": secondPartial},
			},
		},
	}})
	first := invokeStreamBody(t, formatGemini, requestBody, 0, firstBody)
	if got := geminiStreamText(t, deliveredStreamBody(first, firstBody)); strings.Contains(got, firstPartial) || strings.Contains(got, secondPartial) {
		t.Fatalf("pending Gemini terminal prefixes reached the client: %q", got)
	}

	terminalBody := geminiCandidatesBody(t, []any{map[string]any{
		"index":        4,
		"finishReason": "STOP",
		"metadata":     "preserved",
	}})
	terminal := invokeStreamBody(t, formatGemini, requestBody, 1, terminalBody)
	var doc struct {
		Candidates []struct {
			Index        int    `json:"index"`
			FinishReason string `json:"finishReason"`
			Metadata     string `json:"metadata"`
			Content      struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(deliveredStreamBody(terminal, terminalBody), &doc); err != nil {
		t.Fatalf("unmarshal terminal Gemini body: %v", err)
	}
	if len(doc.Candidates) != 1 {
		t.Fatalf("terminal candidate count changed: %#v", doc)
	}
	candidate := doc.Candidates[0]
	if candidate.Index != 4 || candidate.FinishReason != "STOP" || candidate.Metadata != "preserved" {
		t.Fatalf("terminal candidate fields changed: %#v", candidate)
	}
	if len(candidate.Content.Parts) != 2 || candidate.Content.Parts[0].Text != firstPartial || candidate.Content.Parts[1].Text != secondPartial {
		t.Fatalf("pending Gemini parts were not flushed in part-index order: %#v", candidate.Content.Parts)
	}
}

func TestGeminiStreamKeepsCandidateAndPartIndicesIndependent(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secrets := []string{
		"gemini-candidate-seven-part-zero",
		"gemini-candidate-seven-part-one",
		"gemini-candidate-eleven-part-zero",
		"gemini-candidate-eleven-part-one",
	}
	tokens := make([]string, len(secrets))
	var requestText strings.Builder
	for i, secret := range secrets {
		tokens[i] = makeToken(st.label, secret)
		st.vault.Put(tokens[i], secret)
		requestText.WriteString(tokens[i])
		requestText.WriteByte(' ')
	}
	requestBody := []byte(`{"contents":[{"parts":[{"text":"` + requestText.String() + `"}]}]}`)
	resetStreamCarry(requestBody)
	splits := make([]int, len(tokens))
	for i := range tokens {
		splits[i] = len(tokens[i]) / 2
	}

	firstBody := geminiCandidatesBody(t, []any{
		geminiCandidate(7, tokens[0][:splits[0]], tokens[1][:splits[1]]),
		geminiCandidate(11, tokens[2][:splits[2]], tokens[3][:splits[3]]),
	})
	first := invokeStreamBody(t, formatGemini, requestBody, 0, firstBody)
	firstDelivered := geminiStreamText(t, deliveredStreamBody(first, firstBody))
	for i, token := range tokens {
		if strings.Contains(firstDelivered, token[:splits[i]]) {
			t.Fatalf("candidate/part %d prefix reached the client: %q", i, firstDelivered)
		}
	}

	secondBody := geminiCandidatesBody(t, []any{
		geminiCandidate(11, tokens[2][splits[2]:], tokens[3][splits[3]:]),
		geminiCandidate(7, tokens[0][splits[0]:], tokens[1][splits[1]:]),
	})
	second := invokeStreamBody(t, formatGemini, requestBody, 1, secondBody)
	var doc struct {
		Candidates []struct {
			Index   int `json:"index"`
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(deliveredStreamBody(second, secondBody), &doc); err != nil {
		t.Fatalf("unmarshal independent Gemini candidates: %v", err)
	}
	got := make(map[int][]string, len(doc.Candidates))
	for _, candidate := range doc.Candidates {
		for _, part := range candidate.Content.Parts {
			got[candidate.Index] = append(got[candidate.Index], part.Text)
		}
	}
	if strings.Join(got[7], "|") != strings.Join(secrets[:2], "|") || strings.Join(got[11], "|") != strings.Join(secrets[2:], "|") {
		t.Fatalf("Gemini candidate/part channels interfered: %#v", got)
	}
}

func TestGeminiStreamLeavesNonVisibleAndInvalidBareJSONUnchanged(t *testing.T) {
	tests := []struct {
		name        string
		body        func(string) []byte
		wantRestore bool
	}{
		{
			name: "thought part",
			body: func(token string) []byte {
				return mustJSONMarshal(t, map[string]any{"candidates": []any{map[string]any{
					"index": 0,
					"content": map[string]any{"parts": []any{map[string]any{
						"thought": true,
						"text":    token,
					}}},
				}}})
			},
		},
		{
			name: "null text",
			body: func(token string) []byte {
				return mustJSONMarshal(t, map[string]any{"candidates": []any{map[string]any{
					"index":    0,
					"metadata": token,
					"content":  map[string]any{"parts": []any{map[string]any{"text": nil}}},
				}}})
			},
		},
		{
			name: "invalid candidate index",
			body: func(token string) []byte {
				return mustJSONMarshal(t, map[string]any{"candidates": []any{map[string]any{
					"index":   "0",
					"content": map[string]any{"parts": []any{map[string]any{"text": token}}},
				}}})
			},
		},
		{
			name: "malformed JSON",
			body: func(token string) []byte {
				return []byte(`{"candidates":[{"index":0,"content":{"parts":[{"text":"` + token + `"}]}}]`)
			},
		},
		{
			name: "non-Gemini JSON",
			body: func(token string) []byte {
				return mustJSONMarshal(t, map[string]any{"result": map[string]any{"text": token}})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callRegister(t, pluginabi.MethodPluginRegister, "")
			st := activeSnapshot()
			secret := "gemini-negative-" + tt.name
			token := makeToken(st.label, secret)
			st.vault.Put(token, secret)
			requestBody := []byte(`{"contents":[{"parts":[{"text":"` + token + `"}]}]}`)
			resetStreamCarry(requestBody)
			body := tt.body(token)

			response := invokeStreamBody(t, formatGemini, requestBody, 0, body)
			delivered := deliveredStreamBody(response, body)
			if tt.wantRestore {
				if !bytes.Contains(delivered, []byte(secret)) || bytes.Contains(delivered, []byte(token)) {
					t.Fatalf("malformed/non-semantic Gemini field did not use generic restoration: %q", delivered)
				}
			} else if !bytes.Equal(delivered, body) {
				t.Fatalf("excluded or unsupported Gemini body changed: got %q want %q", delivered, body)
			}
		})
	}
}

func TestGeminiUnchangedBareJSONRemainsByteIdentical(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	token := makeToken(st.label, "gemini-unchanged-request-secret")
	st.vault.Put(token, "gemini-unchanged-request-secret")
	requestBody := []byte(`{"contents":[{"parts":[{"text":"` + token + `"}]}]}`)
	resetStreamCarry(requestBody)
	body := []byte(" { \"candidates\" : [ { \"content\" : { \"parts\" : [ { \"text\" : \"plain\" } ] } } ] }\n")

	response := invokeStreamBody(t, formatGemini, requestBody, 0, body)
	if delivered := deliveredStreamBody(response, body); !bytes.Equal(delivered, body) {
		t.Fatalf("unchanged Gemini JSON was re-encoded: got %q want %q", delivered, body)
	}
}

func TestMalformedSemanticEventsRemainOpaque(t *testing.T) {
	type bodiesFunc func(*testing.T, string, string) ([]byte, []byte)
	tests := []struct {
		name         string
		sourceFormat string
		bodies       bodiesFunc
		streamText   func(*testing.T, []byte) string
		channel      string
	}{
		{
			name:         "OpenAI Chat rejects all choices",
			sourceFormat: formatOpenAI,
			bodies: func(t *testing.T, prefix, token string) ([]byte, []byte) {
				makeBody := func(choices []any) []byte {
					payload := mustJSONMarshal(t, map[string]any{"object": "chat.completion.chunk", "choices": choices})
					return append(append([]byte("data: "), payload...), '\n', '\n')
				}
				seed := makeBody([]any{map[string]any{"index": 0, "delta": map[string]any{"content": prefix}}})
				malformed := makeBody([]any{
					map[string]any{"index": 0, "delta": map[string]any{"content": token[len(prefix):]}},
					map[string]any{"delta": map[string]any{"content": token}},
				})
				return seed, malformed
			},
			streamText: openAIStreamContent,
			channel:    "openai:choice:0",
		},
		{
			name:         "Responses negative output index",
			sourceFormat: formatOpenAIResponse,
			bodies: func(t *testing.T, prefix, token string) ([]byte, []byte) {
				makeBody := func(index int, text string) []byte {
					return responsesSSEBody(t, "response.output_text.delta", map[string]any{
						"type":          "response.output_text.delta",
						"item_id":       "msg_opaque",
						"output_index":  index,
						"content_index": 0,
						"delta":         text,
					}, "\n")
				}
				return makeBody(0, prefix), makeBody(-1, token)
			},
			streamText: openAIResponsesStreamText,
			channel:    "openai-response:output:0:content:0:item:msg_opaque",
		},
		{
			name:         "Claude negative block index",
			sourceFormat: formatClaude,
			bodies: func(t *testing.T, prefix, token string) ([]byte, []byte) {
				makeBody := func(index int, text string) []byte {
					return claudeSSEBody(t, "content_block_delta", map[string]any{
						"type":  "content_block_delta",
						"index": index,
						"delta": map[string]any{"type": "text_delta", "text": text},
					}, "\n")
				}
				return makeBody(0, prefix), makeBody(-1, token)
			},
			streamText: claudeStreamText,
			channel:    "claude:block:0",
		},
		{
			name:         "Gemini rejects all candidates",
			sourceFormat: formatGemini,
			bodies: func(t *testing.T, prefix, token string) ([]byte, []byte) {
				seed := geminiCandidatesBody(t, []any{geminiCandidate(0, prefix)})
				malformed := geminiCandidatesBody(t, []any{
					geminiCandidate(0, token[len(prefix):]),
					map[string]any{"index": "1", "content": map[string]any{"parts": []any{map[string]any{"text": token}}}},
				})
				return seed, malformed
			},
			streamText: geminiStreamText,
			channel:    "gemini:candidate:0:part:0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callRegister(t, pluginabi.MethodPluginRegister, "")
			st := activeSnapshot()
			secret := "malformed-index-secret-" + tt.name
			token := makeToken(st.label, secret)
			st.vault.Put(token, secret)
			requestBody := []byte(`{"input":"` + token + `"}`)
			resetStreamCarry(requestBody)
			split := len(token) / 2
			seedBody, malformedBody := tt.bodies(t, token[:split], token)

			seed := invokeStreamBody(t, tt.sourceFormat, requestBody, 0, seedBody)
			if got := tt.streamText(t, deliveredStreamBody(seed, seedBody)); got != "" {
				t.Fatalf("seed prefix reached the client: %q", got)
			}
			key := streamKey(requestBody)
			streamCarry.mu.Lock()
			entry := streamCarry.entries[key]
			if entry == nil || len(entry.content) != 1 || entry.content[tt.channel] != token[:split] {
				var content map[string]string
				if entry != nil {
					content = entry.content
				}
				streamCarry.mu.Unlock()
				t.Fatalf("seed pending state changed: %#v", content)
			}
			streamCarry.mu.Unlock()

			malformed := invokeStreamBody(t, tt.sourceFormat, requestBody, 1, malformedBody)
			delivered := deliveredStreamBody(malformed, malformedBody)
			if !bytes.Equal(delivered, malformedBody) {
				t.Fatalf("malformed recognized event changed: got %q want %q", delivered, malformedBody)
			}
			if bytes.Contains(delivered, []byte(secret)) {
				t.Fatalf("malformed recognized event emitted the secret: %q", delivered)
			}
			streamCarry.mu.Lock()
			entry = streamCarry.entries[key]
			if entry == nil || len(entry.content) != 1 || entry.content[tt.channel] != token[:split] {
				var content map[string]string
				if entry != nil {
					content = entry.content
				}
				streamCarry.mu.Unlock()
				t.Fatalf("malformed recognized event created or consumed pending state: %#v", content)
			}
			streamCarry.mu.Unlock()
		})
	}
}

func TestUnknownSemanticEventTypesKeepGenericRestoration(t *testing.T) {
	tests := []struct {
		name         string
		sourceFormat string
		doc          func(string) map[string]any
	}{
		{name: "OpenAI Chat", sourceFormat: formatOpenAI, doc: func(token string) map[string]any {
			return map[string]any{"object": "custom.chunk", "text": token}
		}},
		{name: "Responses", sourceFormat: formatOpenAIResponse, doc: func(token string) map[string]any {
			return map[string]any{"type": "response.custom", "text": token}
		}},
		{name: "Claude", sourceFormat: formatClaude, doc: func(token string) map[string]any {
			return map[string]any{"type": "custom_event", "text": token}
		}},
		{name: "Gemini", sourceFormat: formatGemini, doc: func(token string) map[string]any {
			return map[string]any{"result": map[string]any{"text": token}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callRegister(t, pluginabi.MethodPluginRegister, "")
			st := activeSnapshot()
			secret := "unknown-event-secret-" + tt.name
			token := makeToken(st.label, secret)
			st.vault.Put(token, secret)
			requestBody := []byte(`{"input":"` + token + `"}`)
			resetStreamCarry(requestBody)
			payload := mustJSONMarshal(t, tt.doc(token))
			body := append(append([]byte("data: "), payload...), '\n', '\n')

			response := invokeStreamBody(t, tt.sourceFormat, requestBody, 0, body)
			delivered := deliveredStreamBody(response, body)
			if !bytes.Contains(delivered, []byte(secret)) || bytes.Contains(delivered, []byte(token)) {
				t.Fatalf("unknown event lost generic restoration: %q", delivered)
			}
		})
	}
}

func TestSemanticSSEPreservesExactDataLeadingWhitespace(t *testing.T) {
	t.Run("rewritten original frame", func(t *testing.T) {
		callRegister(t, pluginabi.MethodPluginRegister, "")
		st := activeSnapshot()
		secret := "exact-data-lead-original"
		token := makeToken(st.label, secret)
		st.vault.Put(token, secret)
		requestBody := []byte(`{"input":"` + token + `"}`)
		resetStreamCarry(requestBody)
		payload := mustJSONMarshal(t, map[string]any{
			"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": token,
		})
		lead := "\t  \t"
		body := []byte("event: response.output_text.delta\r\ndata:" + lead + string(payload) + "\r\n\r\n")

		response := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, body)
		delivered := deliveredStreamBody(response, body)
		wantPrefix := []byte("event: response.output_text.delta\r\ndata:" + lead + "{")
		if !bytes.HasPrefix(delivered, wantPrefix) || !bytes.Contains(delivered, []byte(secret)) {
			t.Fatalf("rewritten frame lost exact data lead: got %q want prefix %q", delivered, wantPrefix)
		}
	})

	t.Run("synthetic terminal frame", func(t *testing.T) {
		callRegister(t, pluginabi.MethodPluginRegister, "")
		st := activeSnapshot()
		secret := "exact-data-lead-synthetic"
		token := makeToken(st.label, secret)
		st.vault.Put(token, secret)
		requestBody := []byte(`{"input":"` + token + `"}`)
		resetStreamCarry(requestBody)
		partial := token[:len(token)/2]
		seedBody := responsesOutputTextDeltaBody(t, partial)
		invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, seedBody)
		payload := mustJSONMarshal(t, map[string]any{
			"type": "response.output_text.done", "item_id": "msg_privacy", "output_index": 0, "content_index": 0, "text": partial,
		})
		lead := " \t  "
		body := []byte("event: response.output_text.done\r\ndata:" + lead + string(payload) + "\r\n\r\n")

		response := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, body)
		delivered := deliveredStreamBody(response, body)
		wantPrefix := []byte("event: response.output_text.delta\r\ndata:" + lead + "{")
		if !bytes.HasPrefix(delivered, wantPrefix) {
			t.Fatalf("synthetic frame lost exact data lead: got %q want prefix %q", delivered, wantPrefix)
		}
	})
}

func TestClaudeStreamFlushesIncompleteTokenAtContentBlockStop(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "claude-unfinished-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	partial := token[:len(token)/2]

	firstBody := claudeTextDeltaBody(t, 3, partial)
	first := invokeStreamBody(t, formatClaude, requestBody, 0, firstBody)
	if got := claudeStreamText(t, deliveredStreamBody(first, firstBody)); got != "" {
		t.Fatalf("partial Claude token was emitted before block stop: %q", got)
	}
	stopBody := claudeSSEBody(t, "content_block_stop", map[string]any{
		"type":  "content_block_stop",
		"index": 3,
	}, "\n")
	stopped := invokeStreamBody(t, formatClaude, requestBody, 1, stopBody)
	delivered := deliveredStreamBody(stopped, stopBody)
	if got := claudeStreamText(t, delivered); got != partial {
		t.Fatalf("incomplete Claude token prefix was not flushed: got %q want %q", got, partial)
	}
	deltaEvent := bytes.Index(delivered, []byte("event: content_block_delta\n"))
	stopEvent := bytes.Index(delivered, []byte("event: content_block_stop\n"))
	if deltaEvent < 0 || stopEvent < 0 || deltaEvent >= stopEvent {
		t.Fatalf("synthetic Claude delta was not inserted before block stop: %q", delivered)
	}
	frames := parseSemanticSSEFrames(delivered)
	if len(frames) != 2 || frames[0].event != "content_block_delta" {
		t.Fatalf("synthetic Claude delta frame is invalid: %q", delivered)
	}
	synthetic, ok := frames[0].doc.(map[string]any)
	if !ok {
		t.Fatalf("synthetic Claude delta is not an object: %#v", frames[0].doc)
	}
	index, indexOK := synthetic["index"].(json.Number)
	delta, deltaOK := synthetic["delta"].(map[string]any)
	if synthetic["type"] != "content_block_delta" || !indexOK || index.String() != "3" || !deltaOK || delta["type"] != "text_delta" || delta["text"] != partial {
		t.Fatalf("synthetic Claude delta shape changed: %#v", synthetic)
	}
}

func TestClaudeStreamKeepsBlockIndicesIndependent(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	firstSecret := "claude-first-block-secret"
	secondSecret := "claude-second-block-secret"
	firstToken := makeToken(st.label, firstSecret)
	secondToken := makeToken(st.label, secondSecret)
	st.vault.Put(firstToken, firstSecret)
	st.vault.Put(secondToken, secondSecret)
	requestBody := []byte(`{"messages":[{"content":"` + firstToken + ` ` + secondToken + `"}]}`)
	resetStreamCarry(requestBody)
	firstSplit := len(firstToken) / 2
	secondSplit := len(secondToken) / 2

	firstBody := claudeTextDeltaBody(t, 0, firstToken[:firstSplit])
	first := invokeStreamBody(t, formatClaude, requestBody, 0, firstBody)
	if got := claudeStreamText(t, deliveredStreamBody(first, firstBody)); got != "" {
		t.Fatalf("first Claude block prefix was emitted: %q", got)
	}
	secondBody := claudeTextDeltaBody(t, 1, secondToken[:secondSplit])
	second := invokeStreamBody(t, formatClaude, requestBody, 1, secondBody)
	if got := claudeStreamText(t, deliveredStreamBody(second, secondBody)); got != "" {
		t.Fatalf("second Claude block prefix was emitted: %q", got)
	}
	firstCompletionBody := claudeTextDeltaBody(t, 0, firstToken[firstSplit:])
	firstCompletion := invokeStreamBody(t, formatClaude, requestBody, 2, firstCompletionBody)
	if got := claudeStreamText(t, deliveredStreamBody(firstCompletion, firstCompletionBody)); got != firstSecret {
		t.Fatalf("first Claude block did not restore independently: %q", got)
	}
	secondCompletionBody := claudeTextDeltaBody(t, 1, secondToken[secondSplit:])
	secondCompletion := invokeStreamBody(t, formatClaude, requestBody, 3, secondCompletionBody)
	if got := claudeStreamText(t, deliveredStreamBody(secondCompletion, secondCompletionBody)); got != secondSecret {
		t.Fatalf("second Claude block did not restore independently: %q", got)
	}
}

func TestClaudeInputJSONDeltaChannelsRemainIsolated(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secrets := []string{"claude-tool-block-two", "claude-tool-block-seven"}
	tokens := []string{makeToken(st.label, secrets[0]), makeToken(st.label, secrets[1])}
	for i := range tokens {
		st.vault.Put(tokens[i], secrets[i])
	}
	requestBody := []byte(`{"messages":[{"content":"` + tokens[0] + ` ` + tokens[1] + `"}]}`)
	resetStreamCarry(requestBody)
	splits := []int{len(tokens[0]) / 2, len(tokens[1]) / 2}

	var delivered []byte
	fragments := []struct {
		index    int
		fragment string
	}{
		{index: 2, fragment: `{"value":"` + tokens[0][:splits[0]]},
		{index: 7, fragment: `{"value":"` + tokens[1][:splits[1]]},
		{index: 7, fragment: tokens[1][splits[1]:] + `"}`},
		{index: 2, fragment: tokens[0][splits[0]:] + `"}`},
	}
	for chunkIndex, fragment := range fragments {
		body := claudeInputJSONDeltaBody(t, fragment.index, fragment.fragment)
		response := invokeStreamBody(t, formatClaude, requestBody, chunkIndex, body)
		delivered = append(delivered, deliveredStreamBody(response, body)...)
	}

	arguments := claudeInputJSONByBlock(t, delivered)
	for i, index := range []int64{2, 7} {
		var decoded map[string]string
		if err := json.Unmarshal([]byte(arguments[index]), &decoded); err != nil {
			t.Fatalf("Claude block %d produced invalid input JSON %q: %v", index, arguments[index], err)
		}
		if got := decoded["value"]; got != secrets[i] {
			t.Fatalf("Claude block %d restored value = %q, want %q", index, got, secrets[i])
		}
	}
}

func TestClaudeInputJSONContentBlockStopFlushesOnlyMatchingBlock(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	token := makeToken(st.label, "claude-input-json-block-stop")
	st.vault.Put(token, "claude-input-json-block-stop")
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	partial := token[:len(token)/2]

	for chunkIndex, index := range []int{3, 8} {
		body := claudeInputJSONDeltaBody(t, index, `{"value":"`+partial)
		response := invokeStreamBody(t, formatClaude, requestBody, chunkIndex, body)
		_ = deliveredStreamBody(response, body)
	}
	stopBody := claudeSSEBody(t, "content_block_stop", map[string]any{
		"type": "content_block_stop", "index": 3,
	}, "\n")
	stopped := invokeStreamBody(t, formatClaude, requestBody, 2, stopBody)
	flushed := claudeInputJSONByBlock(t, deliveredStreamBody(stopped, stopBody))
	if got := flushed[3]; got != partial {
		t.Fatalf("matching Claude block flush = %q, want %q", got, partial)
	}
	if got := flushed[8]; got != "" {
		t.Fatalf("unmatched Claude block was flushed: %q", got)
	}

	streamCarry.mu.Lock()
	defer streamCarry.mu.Unlock()
	entry := streamCarry.entries[streamKey(requestBody)]
	if entry == nil || len(entry.arguments) != 1 {
		t.Fatalf("Claude block stop retained states = %#v, want only unmatched block", entry)
	}
	if _, exists := entry.arguments["argument:claude:block:8"]; !exists {
		t.Fatalf("unmatched Claude argument state missing: %#v", entry.arguments)
	}
}

func TestClaudeInputJSONMessageStopFlushesAllBlocks(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	token := makeToken(st.label, "claude-input-json-message-stop")
	st.vault.Put(token, "claude-input-json-message-stop")
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	partial := token[:len(token)/2]

	for chunkIndex, index := range []int{1, 6} {
		body := claudeInputJSONDeltaBody(t, index, `{"value":"`+partial)
		response := invokeStreamBody(t, formatClaude, requestBody, chunkIndex, body)
		_ = deliveredStreamBody(response, body)
	}
	stopBody := claudeSSEBody(t, "message_stop", map[string]any{"type": "message_stop"}, "\n")
	stopped := invokeStreamBody(t, formatClaude, requestBody, 2, stopBody)
	delivered := deliveredStreamBody(stopped, stopBody)
	flushed := claudeInputJSONByBlock(t, delivered)
	for _, index := range []int64{1, 6} {
		if got := flushed[index]; got != partial {
			t.Fatalf("message_stop flush for block %d = %q, want %q", index, got, partial)
		}
	}
	if !bytes.HasSuffix(delivered, stopBody) {
		t.Fatalf("message_stop event was not preserved at the end: %q", delivered)
	}
	streamCarry.mu.Lock()
	defer streamCarry.mu.Unlock()
	if entry := streamCarry.entries[streamKey(requestBody)]; entry != nil && len(entry.arguments) != 0 {
		t.Fatalf("message_stop retained Claude argument state: %#v", entry.arguments)
	}
}

func TestClaudeInputJSONDeltaRejectsInvalidBlockIndex(t *testing.T) {
	label := "REDACTED"
	token := makeToken(label, "invalid-claude-input-index")
	fragment := `{"value":"` + token[:len(token)/2]
	for _, tc := range []struct {
		name  string
		index any
		omit  bool
	}{
		{name: "missing", omit: true},
		{name: "negative", index: -1},
		{name: "non-integer", index: 0.5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := "invalid-claude-input-index-" + tc.name
			streamCarry.reset(key)
			doc := map[string]any{
				"type":  "content_block_delta",
				"delta": map[string]any{"type": "input_json_delta", "partial_json": fragment},
			}
			if !tc.omit {
				doc["index"] = tc.index
			}
			body := claudeSSEBody(t, "content_block_delta", doc, "\n")
			out, handled := restoreSemanticStream(key, body, tokenPattern(label), []string{label}, map[string]struct{}{token: {}}, newVault(1, time.Hour), "text/event-stream", formatClaude)
			if !handled || !bytes.Equal(out, body) {
				t.Fatalf("invalid Claude block index changed fragment: handled=%v out=%q want=%q", handled, out, body)
			}
			streamCarry.mu.Lock()
			entry := streamCarry.entries[key]
			if entry != nil && entry.arguments != nil {
				streamCarry.mu.Unlock()
				t.Fatalf("invalid Claude block index created argument state: %#v", entry.arguments)
			}
			streamCarry.mu.Unlock()
		})
	}
}

func TestClaudeInputJSONDeltaSpecialCharactersRemainValid(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "quote=\" slash=\\ line=\n tab=\t control=\x01 unicode=世界 html=<>&"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2

	firstBody := claudeInputJSONDeltaBody(t, 4, `{"value":"`+token[:split])
	first := invokeStreamBody(t, formatClaude, requestBody, 0, firstBody)
	secondBody := claudeInputJSONDeltaBody(t, 4, token[split:]+`"}`)
	second := invokeStreamBody(t, formatClaude, requestBody, 1, secondBody)
	delivered := append(deliveredStreamBody(first, firstBody), deliveredStreamBody(second, secondBody)...)
	argument := claudeInputJSONByBlock(t, delivered)[4]
	var decoded map[string]string
	if err := json.Unmarshal([]byte(argument), &decoded); err != nil {
		t.Fatalf("special-character Claude input JSON is invalid %q: %v", argument, err)
	}
	if got := decoded["value"]; got != secret {
		t.Fatalf("special-character Claude value = %q, want %q", got, secret)
	}
}

func TestClaudeStreamPreservesMetadataEventNameAndCRLF(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "claude-metadata-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	body := claudeSSEBody(t, "content_block_delta", map[string]any{
		"type":     "content_block_delta",
		"index":    2,
		"metadata": "preserved",
		"delta": map[string]any{
			"type": "text_delta",
			"text": token,
		},
	}, "\r\n")

	response := invokeStreamBody(t, formatClaude, requestBody, 0, body)
	delivered := deliveredStreamBody(response, body)
	if bytes.Contains(delivered, []byte(token)) || !bytes.Contains(delivered, []byte(secret)) {
		t.Fatalf("Claude visible text was not restored: %q", delivered)
	}
	frames := parseSemanticSSEFrames(delivered)
	if len(frames) != 1 || frames[0].event != "content_block_delta" || !bytes.Equal(frames[0].lineEnding, []byte("\r\n")) {
		t.Fatalf("Claude event name or CRLF changed: %q", delivered)
	}
	root, ok := frames[0].doc.(map[string]any)
	if !ok || root["type"] != "content_block_delta" || root["metadata"] != "preserved" {
		t.Fatalf("Claude event metadata changed: %#v", frames[0].doc)
	}
	index, indexOK := root["index"].(json.Number)
	if !indexOK || index.String() != "2" {
		t.Fatalf("Claude block index changed: %#v", root["index"])
	}
	withoutCRLF := bytes.ReplaceAll(delivered, []byte("\r\n"), nil)
	if bytes.ContainsAny(withoutCRLF, "\r\n") {
		t.Fatalf("Claude stream contains a non-CRLF line ending: %q", delivered)
	}
}

func TestClaudeStreamThinkingAndToolDeltasDoNotShareTextPending(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	textSecret := "claude-visible-only-secret"
	argumentSecret := "claude-input-json-only-secret"
	textToken := makeToken(st.label, textSecret)
	argumentToken := makeToken(st.label, argumentSecret)
	st.vault.Put(textToken, textSecret)
	st.vault.Put(argumentToken, argumentSecret)
	requestBody := []byte(`{"messages":[{"content":"` + textToken + ` ` + argumentToken + `"}]}`)
	resetStreamCarry(requestBody)
	textSplit := len(textToken) / 2
	argumentSplit := len(argumentToken) / 2

	firstBody := claudeTextDeltaBody(t, 0, textToken[:textSplit])
	invokeStreamBody(t, formatClaude, requestBody, 0, firstBody)
	thinkingBody := claudeSSEBody(t, "content_block_delta", map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{"type": "thinking_delta", "thinking": textToken[textSplit:]},
	}, "\n")
	thinking := invokeStreamBody(t, formatClaude, requestBody, 1, thinkingBody)
	if delivered := deliveredStreamBody(thinking, thinkingBody); !bytes.Equal(delivered, thinkingBody) || bytes.Contains(delivered, []byte(textSecret)) {
		t.Fatalf("Claude thinking delta entered text pending state: %q", delivered)
	}
	argumentFirstBody := claudeInputJSONDeltaBody(t, 0, `{"value":"`+argumentToken[:argumentSplit])
	argumentFirst := invokeStreamBody(t, formatClaude, requestBody, 2, argumentFirstBody)
	if got := claudeInputJSONByBlock(t, deliveredStreamBody(argumentFirst, argumentFirstBody))[0]; got != `{"value":"` {
		t.Fatalf("Claude input JSON prefix output = %q", got)
	}
	argumentSecondBody := claudeInputJSONDeltaBody(t, 0, argumentToken[argumentSplit:]+`"}`)
	argumentSecond := invokeStreamBody(t, formatClaude, requestBody, 3, argumentSecondBody)
	argument := claudeInputJSONByBlock(t, append(deliveredStreamBody(argumentFirst, argumentFirstBody), deliveredStreamBody(argumentSecond, argumentSecondBody)...))[0]
	var decoded map[string]string
	if err := json.Unmarshal([]byte(argument), &decoded); err != nil || decoded["value"] != argumentSecret {
		t.Fatalf("Claude input JSON state was changed by text/thinking: argument=%q decoded=%#v err=%v", argument, decoded, err)
	}
	completionBody := claudeTextDeltaBody(t, 0, textToken[textSplit:])
	completion := invokeStreamBody(t, formatClaude, requestBody, 4, completionBody)
	if got := claudeStreamText(t, deliveredStreamBody(completion, completionBody)); got != textSecret {
		t.Fatalf("Claude text pending state was changed by thinking/tool deltas: %q", got)
	}
}

func TestClaudeStreamPreservesInvalidTextDeltaFields(t *testing.T) {
	tests := []struct {
		name  string
		delta map[string]any
	}{
		{name: "null", delta: map[string]any{"type": "text_delta", "text": nil}},
		{name: "missing", delta: map[string]any{"type": "text_delta"}},
		{name: "non-string", delta: map[string]any{"type": "text_delta", "text": 42}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callRegister(t, pluginabi.MethodPluginRegister, "")
			st := activeSnapshot()
			secret := "claude-invalid-text-secret-" + tt.name
			token := makeToken(st.label, secret)
			st.vault.Put(token, secret)
			requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
			resetStreamCarry(requestBody)
			split := len(token) / 2

			firstBody := claudeTextDeltaBody(t, 0, token[:split])
			invokeStreamBody(t, formatClaude, requestBody, 0, firstBody)
			body := claudeSSEBody(t, "content_block_delta", map[string]any{
				"type":  "content_block_delta",
				"index": 0,
				"delta": tt.delta,
			}, "\n")
			response := invokeStreamBody(t, formatClaude, requestBody, 1, body)
			if delivered := deliveredStreamBody(response, body); !bytes.Equal(delivered, body) {
				t.Fatalf("invalid Claude delta.text was not preserved: got %q want %q", delivered, body)
			}
			completionBody := claudeTextDeltaBody(t, 0, token[split:])
			completion := invokeStreamBody(t, formatClaude, requestBody, 2, completionBody)
			if got := claudeStreamText(t, deliveredStreamBody(completion, completionBody)); got != secret {
				t.Fatalf("invalid Claude delta.text changed pending state: %q", got)
			}
		})
	}
}

func TestOpenAIResponsesSparseDoneFlushDoesNotInventOptionalFields(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-sparse-done-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)
	partial := token[:len(token)/2]

	firstBody := responsesSSEBody(t, "response.output_text.delta", map[string]any{
		"type":          "response.output_text.delta",
		"output_index":  2,
		"content_index": 3,
		"delta":         partial,
	}, "\n")
	first := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, firstBody)
	if got := openAIResponsesStreamText(t, deliveredStreamBody(first, firstBody)); got != "" {
		t.Fatalf("sparse Responses prefix reached the client: %q", got)
	}
	doneBody := responsesSSEBody(t, "response.output_text.done", map[string]any{
		"type":          "response.output_text.done",
		"output_index":  2,
		"content_index": 3,
		"text":          partial,
	}, "\n")
	done := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, doneBody)
	delivered := deliveredStreamBody(done, doneBody)
	if got := openAIResponsesStreamText(t, delivered); got != partial {
		t.Fatalf("sparse done did not flush pending text: got %q want %q", got, partial)
	}
	frames := parseSemanticSSEFrames(delivered)
	if len(frames) != 2 || frames[0].event != "response.output_text.delta" || frames[1].event != "response.output_text.done" {
		t.Fatalf("sparse synthetic delta ordering changed: %q", delivered)
	}
	synthetic := frames[0].doc.(map[string]any)
	for _, field := range []string{"item_id", "sequence_number", "logprobs"} {
		if _, exists := synthetic[field]; exists {
			t.Fatalf("sparse synthetic delta invented %s: %#v", field, synthetic)
		}
	}
	outputIndex, outputOK := synthetic["output_index"].(json.Number)
	contentIndex, contentOK := synthetic["content_index"].(json.Number)
	if synthetic["type"] != "response.output_text.delta" || synthetic["delta"] != partial || !outputOK || outputIndex.String() != "2" || !contentOK || contentIndex.String() != "3" {
		t.Fatalf("sparse synthetic delta lost indices or text: %#v", synthetic)
	}
}

func TestOpenAIResponsesStreamFlushesIncompleteTokenAtOutputTextDone(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-unfinished-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)
	partial := token[:len(token)/2]

	firstBody := responsesOutputTextDeltaBody(t, partial)
	first := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, firstBody)
	if got := openAIResponsesStreamText(t, deliveredStreamBody(first, firstBody)); got != "" {
		t.Fatalf("partial Responses token was emitted before done: %q", got)
	}
	doneBody := responsesSSEBody(t, "response.output_text.done", map[string]any{
		"type":            "response.output_text.done",
		"item_id":         "msg_privacy",
		"output_index":    0,
		"content_index":   0,
		"sequence_number": 2,
		"logprobs":        []any{map[string]any{"token": "terminal", "logprob": -0.25}},
		"text":            partial,
	}, "\r\n")
	done := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, doneBody)
	delivered := deliveredStreamBody(done, doneBody)
	if got := openAIResponsesStreamText(t, delivered); got != partial {
		t.Fatalf("incomplete Responses token prefix was not flushed: got %q want %q", got, partial)
	}
	deltaEvent := bytes.Index(delivered, []byte("event: response.output_text.delta\r\n"))
	doneEvent := bytes.Index(delivered, []byte("event: response.output_text.done\r\n"))
	if deltaEvent < 0 || doneEvent < 0 || deltaEvent >= doneEvent {
		t.Fatalf("synthetic delta was not inserted before done: %q", delivered)
	}
	frames := parseSemanticSSEFrames(delivered)
	if len(frames) != 2 || frames[0].event != "response.output_text.delta" {
		t.Fatalf("synthetic Responses delta frame is invalid: %q", delivered)
	}
	synthetic, ok := frames[0].doc.(map[string]any)
	if !ok {
		t.Fatalf("synthetic Responses delta is not an object: %#v", frames[0].doc)
	}
	outputIndex, outputOK := synthetic["output_index"].(json.Number)
	contentIndex, contentOK := synthetic["content_index"].(json.Number)
	sequence, sequenceOK := synthetic["sequence_number"].(json.Number)
	logprobs, logprobsOK := synthetic["logprobs"].([]any)
	if synthetic["type"] != "response.output_text.delta" || synthetic["item_id"] != "msg_privacy" || !outputOK || outputIndex.String() != "0" || !contentOK || contentIndex.String() != "0" || !sequenceOK || sequence.String() != "2" || !logprobsOK || len(logprobs) != 1 {
		t.Fatalf("synthetic Responses delta identity or indices changed: %#v", synthetic)
	}
	logprob, logprobOK := logprobs[0].(map[string]any)
	if !logprobOK || logprob["token"] != "terminal" {
		t.Fatalf("synthetic Responses delta logprobs changed: %#v", synthetic["logprobs"])
	}
}

func TestOpenAIResponsesStreamPreservesMetadataEventNamesAndCRLF(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "responses-metadata-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)

	deltaBody := responsesSSEBody(t, "response.output_text.delta", map[string]any{
		"type":            "response.output_text.delta",
		"item_id":         "msg_metadata",
		"output_index":    2,
		"content_index":   3,
		"sequence_number": 40,
		"delta":           token,
	}, "\r\n")
	doneBody := responsesSSEBody(t, "response.output_text.done", map[string]any{
		"type":            "response.output_text.done",
		"item_id":         "msg_metadata",
		"output_index":    2,
		"content_index":   3,
		"sequence_number": 41,
		"text":            token,
	}, "\r\n")
	body := append(deltaBody, doneBody...)
	response := invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, body)
	delivered := deliveredStreamBody(response, body)
	if bytes.Contains(delivered, []byte(token)) || bytes.Count(delivered, []byte(secret)) != 2 {
		t.Fatalf("Responses visible text was not restored: %q", delivered)
	}

	frames := parseSemanticSSEFrames(delivered)
	if len(frames) != 2 {
		t.Fatalf("expected two preserved Responses frames, got %d: %q", len(frames), delivered)
	}
	wantTypes := []string{"response.output_text.delta", "response.output_text.done"}
	wantSequences := []string{"40", "41"}
	for i, frame := range frames {
		root, ok := frame.doc.(map[string]any)
		if !ok {
			t.Fatalf("Responses frame %d is not an object: %#v", i, frame.doc)
		}
		if frame.event != wantTypes[i] || root["type"] != wantTypes[i] {
			t.Fatalf("Responses event name changed: event=%q type=%#v", frame.event, root["type"])
		}
		if root["item_id"] != "msg_metadata" {
			t.Fatalf("Responses item identity changed: %#v", root["item_id"])
		}
		outputIndex, outputOK := root["output_index"].(json.Number)
		contentIndex, contentOK := root["content_index"].(json.Number)
		sequence, sequenceOK := root["sequence_number"].(json.Number)
		if !outputOK || outputIndex.String() != "2" || !contentOK || contentIndex.String() != "3" || !sequenceOK || sequence.String() != wantSequences[i] {
			t.Fatalf("Responses indices or sequence changed: %#v", root)
		}
		if !bytes.Equal(frame.lineEnding, []byte("\r\n")) {
			t.Fatalf("Responses frame %d lost CRLF: %q", i, delivered)
		}
	}
	withoutCRLF := bytes.ReplaceAll(delivered, []byte("\r\n"), nil)
	if bytes.ContainsAny(withoutCRLF, "\r\n") {
		t.Fatalf("Responses stream contains a non-CRLF line ending: %q", delivered)
	}
}

func TestOpenAIResponsesStreamRestoresEachSecretOnlyOnce(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	innerSecret := "responses-inner-secret"
	innerToken := makeToken(st.label, innerSecret)
	outerToken := makeToken(st.label, innerToken)
	st.vault.Put(innerToken, innerSecret)
	st.vault.Put(outerToken, innerToken)
	requestBody := []byte(`{"input":"` + outerToken + ` ` + innerToken + `"}`)
	resetStreamCarry(requestBody)
	split := len(outerToken) / 2

	firstBody := responsesOutputTextDeltaBody(t, outerToken[:split])
	invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, firstBody)
	secondBody := responsesOutputTextDeltaBody(t, outerToken[split:])
	second := invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, secondBody)
	if got := openAIResponsesStreamText(t, deliveredStreamBody(second, secondBody)); got != innerToken {
		t.Fatalf("Responses restored secret was recursively detokenized: got %q want %q", got, innerToken)
	}
}

func TestOpenAICompletionStreamPreservesTextBetweenSplitTokens(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	firstSecret := "first-stream-secret"
	secondSecret := "second-stream-secret"
	firstToken := makeToken(st.label, firstSecret)
	secondToken := makeToken(st.label, secondSecret)
	st.vault.Put(firstToken, firstSecret)
	st.vault.Put(secondToken, secondSecret)
	requestBody := []byte(`{"messages":[{"content":"` + firstToken + ` ` + secondToken + `"}]}`)
	resetStreamCarry(requestBody)
	firstSplit := len(firstToken) / 2
	secondSplit := len(secondToken) / 2

	first, firstBody := invokeOpenAIContentDelta(t, formatOpenAI, requestBody, 0, "before "+firstToken[:firstSplit])
	if got := openAIStreamContent(t, deliveredStreamBody(first, firstBody)); got != "before " {
		t.Fatalf("safe text before partial token was not preserved: %q", got)
	}
	second, secondBody := invokeOpenAIContentDelta(t, formatOpenAI, requestBody, 1, firstToken[firstSplit:]+" between "+secondToken[:secondSplit])
	if got := openAIStreamContent(t, deliveredStreamBody(second, secondBody)); got != firstSecret+" between " {
		t.Fatalf("completed token or text between tokens was not preserved: %q", got)
	}
	third, thirdBody := invokeOpenAIContentDelta(t, formatOpenAI, requestBody, 2, secondToken[secondSplit:])
	if got := openAIStreamContent(t, deliveredStreamBody(third, thirdBody)); got != secondSecret {
		t.Fatalf("second split token was not restored: %q", got)
	}
}

func TestOpenAICompletionStreamRestoresEachSecretOnlyOnce(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	innerSecret := "inner-stream-secret"
	innerToken := makeToken(st.label, innerSecret)
	outerToken := makeToken(st.label, innerToken)
	st.vault.Put(innerToken, innerSecret)
	st.vault.Put(outerToken, innerToken)
	requestBody := []byte(`{"messages":[{"content":"` + outerToken + ` ` + innerToken + `"}]}`)
	resetStreamCarry(requestBody)
	split := len(outerToken) / 2

	invokeOpenAIContentDelta(t, formatOpenAI, requestBody, 0, outerToken[:split])
	second, secondBody := invokeOpenAIContentDelta(t, formatOpenAI, requestBody, 1, outerToken[split:])
	if got := openAIStreamContent(t, deliveredStreamBody(second, secondBody)); got != innerToken {
		t.Fatalf("restored secret was recursively detokenized: got %q want %q", got, innerToken)
	}
}

func TestOpenAICompletionStreamPreservesNullContentInOtherChoice(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "multi-choice-stream-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2

	invokeOpenAIContentDelta(t, formatOpenAI, requestBody, 0, token[:split])
	payload := mustJSONMarshal(t, map[string]any{
		"id":     "chatcmpl_privacy",
		"object": "chat.completion.chunk",
		"choices": []any{
			map[string]any{"index": 0, "delta": map[string]any{"content": token[split:]}},
			map[string]any{"index": 1, "delta": map[string]any{"content": nil}},
		},
	})
	body := append([]byte("data: "), payload...)
	body = append(body, '\n', '\n')
	response := invokeStreamBody(t, formatOpenAI, requestBody, 1, body)
	delivered := deliveredStreamBody(response, body)
	line, _, _ := nextSSELine(delivered, 0)
	var frame struct {
		Choices []struct {
			Delta map[string]any `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(line[len("data:"):]), &frame); err != nil {
		t.Fatalf("invalid rewritten OpenAI frame: %v", err)
	}
	if value, exists := frame.Choices[1].Delta["content"]; !exists || value != nil {
		t.Fatalf("content:null in unrelated choice was not preserved: %#v", frame.Choices[1].Delta)
	}
}

func TestOpenAICompletionStreamPreservesNullContentWhileTokenPending(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "pending-null-stream-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2

	invokeOpenAIContentDelta(t, formatOpenAI, requestBody, 0, token[:split])
	payload := mustJSONMarshal(t, map[string]any{
		"id":     "chatcmpl_privacy",
		"object": "chat.completion.chunk",
		"choices": []any{map[string]any{
			"index": 0,
			"delta": map[string]any{"content": nil},
		}},
	})
	body := append([]byte("data: "), payload...)
	body = append(body, '\n', '\n')
	response := invokeStreamBody(t, formatOpenAI, requestBody, 1, body)
	delivered := deliveredStreamBody(response, body)
	line, _, _ := nextSSELine(delivered, 0)
	var frame struct {
		Choices []struct {
			Delta map[string]any `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(line[len("data:"):]), &frame); err != nil {
		t.Fatalf("invalid OpenAI frame while token pending: %v", err)
	}
	if value, exists := frame.Choices[0].Delta["content"]; !exists || value != nil {
		t.Fatalf("content:null was changed while token pending: %#v", frame.Choices[0].Delta)
	}

	completed, completedBody := invokeOpenAIContentDelta(t, formatOpenAI, requestBody, 2, token[split:])
	if got := openAIStreamContent(t, deliveredStreamBody(completed, completedBody)); got != secret {
		t.Fatalf("token did not remain pending across content:null: %q", got)
	}
}

func TestOpenAICompletionStreamFlushesIncompleteTokenAtFinish(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "unfinished-stream-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	partial := token[:len(token)/2]

	first, firstBody := invokeOpenAIContentDelta(t, formatOpenAI, requestBody, 0, partial)
	if got := openAIStreamContent(t, deliveredStreamBody(first, firstBody)); got != "" {
		t.Fatalf("partial token was emitted before stream finish: %q", got)
	}
	payload := mustJSONMarshal(t, map[string]any{
		"id":     "chatcmpl_privacy",
		"object": "chat.completion.chunk",
		"choices": []any{map[string]any{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": "stop",
		}},
	})
	body := append([]byte("data: "), payload...)
	body = append(body, '\n', '\n')
	finished := invokeStreamBody(t, formatOpenAI, requestBody, 1, body)
	if got := openAIStreamContent(t, deliveredStreamBody(finished, body)); got != partial {
		t.Fatalf("unfinished token prefix was lost at stream finish: got %q want %q", got, partial)
	}
}

func TestNonOpenAIStreamDoesNotBufferChatCompletionShapedEvents(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "non-openai-stream-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	resetStreamCarry(requestBody)
	split := len(token) / 2

	response, original := invokeOpenAIContentDelta(t, formatClaude, requestBody, 0, token[:split])
	if response.DropChunk || len(response.Body) != 0 {
		t.Fatalf("non-OpenAI stream was modified: %+v", response)
	}
	if delivered := deliveredStreamBody(response, original); !bytes.Equal(delivered, original) {
		t.Fatalf("non-OpenAI stream body changed unexpectedly: %q", delivered)
	}
	response, original = invokeOpenAIContentDelta(t, formatClaude, requestBody, 1, token[split:])
	if response.DropChunk || len(response.Body) != 0 || !bytes.Equal(deliveredStreamBody(response, original), original) {
		t.Fatalf("non-OpenAI stream completion was modified: %+v", response)
	}
}

func invokeOpenAIContentDelta(t *testing.T, sourceFormat string, requestBody []byte, index int, content string) (pluginapi.StreamChunkInterceptResponse, []byte) {
	t.Helper()
	payload := mustJSONMarshal(t, map[string]any{
		"id":     "chatcmpl_privacy",
		"object": "chat.completion.chunk",
		"choices": []any{map[string]any{
			"index": 0,
			"delta": map[string]any{"content": content},
		}},
	})
	body := append([]byte("data: "), payload...)
	body = append(body, '\n', '\n')
	return invokeStreamBody(t, sourceFormat, requestBody, index, body), body
}

func invokeOpenAIBareContentDelta(t *testing.T, requestBody []byte, index int, content string) (pluginapi.StreamChunkInterceptResponse, []byte) {
	t.Helper()
	body := mustJSONMarshal(t, map[string]any{
		"id":     "chatcmpl_privacy",
		"object": "chat.completion.chunk",
		"choices": []any{map[string]any{
			"index": 0,
			"delta": map[string]any{"content": content},
		}},
	})
	return invokeStreamBody(t, formatOpenAI, requestBody, index, body), body
}

func openAIBareStreamContent(t *testing.T, body []byte) string {
	t.Helper()
	if len(body) == 0 {
		return ""
	}
	var frame struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &frame); err != nil {
		t.Fatalf("invalid bare OpenAI stream body: %v (%q)", err, body)
	}
	if len(frame.Choices) == 0 {
		return ""
	}
	return frame.Choices[0].Delta.Content
}

func responsesOutputTextDeltaBody(t *testing.T, delta string) []byte {
	t.Helper()
	return responsesSSEBody(t, "response.output_text.delta", map[string]any{
		"type":          "response.output_text.delta",
		"item_id":       "msg_privacy",
		"output_index":  0,
		"content_index": 0,
		"delta":         delta,
	}, "\n")
}

func claudeTextDeltaBody(t *testing.T, index int, delta string) []byte {
	t.Helper()
	return claudeSSEBody(t, "content_block_delta", map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{
			"type": "text_delta",
			"text": delta,
		},
	}, "\n")
}

func claudeInputJSONDeltaBody(t *testing.T, index int, fragment string) []byte {
	t.Helper()
	return claudeSSEBody(t, "content_block_delta", map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{
			"type":         "input_json_delta",
			"partial_json": fragment,
		},
	}, "\n")
}

func geminiBody(t *testing.T, text string) []byte {
	t.Helper()
	return geminiCandidatesBody(t, []any{map[string]any{
		"index": 0,
		"content": map[string]any{
			"role":  "model",
			"parts": []any{map[string]any{"text": text}},
		},
	}})
}

func geminiCandidatesBody(t *testing.T, candidates []any) []byte {
	t.Helper()
	return mustJSONMarshal(t, map[string]any{"candidates": candidates})
}

func geminiCandidate(index int, texts ...string) map[string]any {
	parts := make([]any, len(texts))
	for i, text := range texts {
		parts[i] = map[string]any{"text": text}
	}
	return map[string]any{
		"index": index,
		"content": map[string]any{
			"role":  "model",
			"parts": parts,
		},
	}
}

func geminiSSEBody(t *testing.T, text string) []byte {
	t.Helper()
	body := append([]byte("data: "), geminiBody(t, text)...)
	return append(body, '\n', '\n')
}

func geminiStreamText(t *testing.T, body []byte) string {
	t.Helper()
	if len(body) == 0 {
		return ""
	}
	var docs []any
	for _, frame := range parseSemanticSSEFrames(body) {
		docs = append(docs, frame.doc)
	}
	if len(docs) == 0 {
		doc, ok := decodeOneJSON(body)
		if !ok {
			t.Fatalf("invalid Gemini stream body: %q", body)
		}
		docs = append(docs, doc)
	}
	var text strings.Builder
	for _, doc := range docs {
		root, ok := doc.(map[string]any)
		if !ok {
			continue
		}
		candidates, _ := root["candidates"].([]any)
		for _, rawCandidate := range candidates {
			candidate, _ := rawCandidate.(map[string]any)
			content, _ := candidate["content"].(map[string]any)
			parts, _ := content["parts"].([]any)
			for _, rawPart := range parts {
				part, _ := rawPart.(map[string]any)
				if thought, _ := part["thought"].(bool); thought {
					continue
				}
				value, _ := part["text"].(string)
				text.WriteString(value)
			}
		}
	}
	return text.String()
}

func claudeSSEBody(t *testing.T, event string, doc map[string]any, lineEnding string) []byte {
	t.Helper()
	payload, ok := encodeSemanticJSON(doc)
	if !ok {
		t.Fatal("marshal Claude SSE event")
	}
	return []byte("event: " + event + lineEnding + "data: " + string(payload) + lineEnding + lineEnding)
}

func claudeStreamText(t *testing.T, body []byte) string {
	t.Helper()
	var text strings.Builder
	for _, frame := range parseSemanticSSEFrames(body) {
		root, ok := frame.doc.(map[string]any)
		if !ok || root["type"] != "content_block_delta" {
			continue
		}
		delta, ok := root["delta"].(map[string]any)
		if !ok || delta["type"] != "text_delta" {
			continue
		}
		value, ok := delta["text"].(string)
		if ok {
			text.WriteString(value)
		}
	}
	return text.String()
}

func claudeInputJSONByBlock(t *testing.T, body []byte) map[int64]string {
	t.Helper()
	arguments := make(map[int64]string)
	for _, frame := range parseSemanticSSEFrames(body) {
		root, ok := frame.doc.(map[string]any)
		if !ok || root["type"] != "content_block_delta" {
			continue
		}
		index, ok := nonnegativeJSONIndex(root["index"])
		if !ok {
			continue
		}
		delta, ok := root["delta"].(map[string]any)
		if !ok || delta["type"] != "input_json_delta" {
			continue
		}
		fragment, ok := delta["partial_json"].(string)
		if ok {
			arguments[index] += fragment
		}
	}
	return arguments
}

func responsesSSEBody(t *testing.T, event string, doc map[string]any, lineEnding string) []byte {
	t.Helper()
	payload, ok := encodeSemanticJSON(doc)
	if !ok {
		t.Fatal("marshal Responses SSE event")
	}
	body := []byte("event: " + event + lineEnding + "data: " + string(payload) + lineEnding + lineEnding)
	return body
}

func openAIResponsesStreamText(t *testing.T, body []byte) string {
	t.Helper()
	var text strings.Builder
	for start := 0; start < len(body); {
		line, _, next := nextSSELine(body, start)
		if bytes.HasPrefix(line, []byte("data:")) {
			var frame struct {
				Type  string `json:"type"`
				Delta string `json:"delta"`
			}
			payload := bytes.TrimSpace(line[len("data:"):])
			if err := json.Unmarshal(payload, &frame); err != nil {
				t.Fatalf("invalid OpenAI Responses SSE frame: %v (%q)", err, payload)
			}
			if frame.Type == "response.output_text.delta" {
				text.WriteString(frame.Delta)
			}
		}
		start = next
	}
	return text.String()
}

func invokeStreamBody(t *testing.T, sourceFormat string, requestBody []byte, index int, body []byte) pluginapi.StreamChunkInterceptResponse {
	t.Helper()
	streamID := streamKey(requestBody)
	if index != pluginapi.StreamChunkHeaderInitIndex && !streamCarry.has(streamID) {
		initStreamWithID(t, sourceFormat, streamID, requestBody)
	}
	wireRequest := pluginapi.StreamChunkInterceptRequest{
		RequestID:       streamID,
		SourceFormat:    sourceFormat,
		ResponseHeaders: http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:            body,
		ChunkIndex:      index,
	}
	if index == pluginapi.StreamChunkHeaderInitIndex {
		wireRequest.RequestBody = requestBody
	}
	req, err := json.Marshal(wireRequest)
	if err != nil {
		t.Fatalf("marshal stream request: %v", err)
	}
	raw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, req)
	if err != nil {
		t.Fatalf("stream intercept: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("stream intercept failed: %+v", env.Error)
	}
	var response pluginapi.StreamChunkInterceptResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return response
}

func deliveredStreamBody(response pluginapi.StreamChunkInterceptResponse, original []byte) []byte {
	if response.DropChunk {
		return nil
	}
	if len(response.Body) > 0 {
		return response.Body
	}
	return original
}

func openAIStreamContent(t *testing.T, body []byte) string {
	t.Helper()
	var content strings.Builder
	for start := 0; start < len(body); {
		line, _, next := nextSSELine(body, start)
		if bytes.HasPrefix(line, []byte("data:")) {
			payload := bytes.TrimSpace(line[len("data:"):])
			var frame struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
				} `json:"choices"`
			}
			if err := json.Unmarshal(payload, &frame); err != nil {
				t.Fatalf("invalid OpenAI SSE frame: %v (%q)", err, payload)
			}
			for _, choice := range frame.Choices {
				content.WriteString(choice.Delta.Content)
			}
		}
		start = next
	}
	return content.String()
}

func TestUnchangedResponseAndChunkReturnNoBody(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	requestBody := []byte(`{"messages":[{"content":"hello"}]}`)
	responseBody := []byte(`{"answer":"hello"}`)

	responseReq, _ := json.Marshal(pluginapi.ResponseInterceptRequest{RequestBody: requestBody, Body: responseBody})
	responseRaw, err := handleMethod(pluginabi.MethodResponseInterceptAfter, responseReq)
	if err != nil {
		t.Fatalf("response intercept: %v", err)
	}
	var responseEnv envelope
	if err := json.Unmarshal(responseRaw, &responseEnv); err != nil {
		t.Fatalf("unmarshal response envelope: %v", err)
	}
	var response pluginapi.ResponseInterceptResponse
	if err := json.Unmarshal(responseEnv.Result, &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(response.Body) != 0 {
		t.Fatalf("unchanged response returned redundant body: %q", response.Body)
	}

	streamID := streamKey(requestBody)
	initStreamWithID(t, formatOpenAI, streamID, requestBody)
	chunkReq, _ := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:  streamID,
		Body:       responseBody,
		ChunkIndex: 0,
	})
	chunkRaw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, chunkReq)
	if err != nil {
		t.Fatalf("chunk intercept: %v", err)
	}
	var chunkEnv envelope
	if err := json.Unmarshal(chunkRaw, &chunkEnv); err != nil {
		t.Fatalf("unmarshal chunk envelope: %v", err)
	}
	var chunk pluginapi.StreamChunkInterceptResponse
	if err := json.Unmarshal(chunkEnv.Result, &chunk); err != nil {
		t.Fatalf("unmarshal chunk: %v", err)
	}
	if len(chunk.Body) != 0 || chunk.DropChunk {
		t.Fatalf("unchanged chunk returned modification: %+v", chunk)
	}
}

// TestRequestInterceptMalformedRejects covers fix #4: a request the plugin
// cannot parse must be rejected (fail closed), never forwarded unredacted.
func TestRequestInterceptMalformedRejects(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")

	raw, err := handleMethod(pluginabi.MethodRequestInterceptBefore, []byte("not json"))
	if err != nil {
		t.Fatalf("handleMethod returned Go error: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("expected ok envelope carrying a Reject response, got %+v", env.Error)
	}
	var wireResponse pluginapi.RequestInterceptResponse
	if err := json.Unmarshal(env.Result, &wireResponse); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	resp := requestResult(t, wireResponse)
	if !resp.Reject {
		t.Fatalf("malformed request must be rejected (fail closed), got %+v", resp)
	}
	if resp.RejectReason == "" {
		t.Fatalf("expected a reject reason")
	}
}

// TestStreamWholeChunkDropped covers fix #5: when an entire chunk is withheld
// (it is only the start of a token split across the boundary), the plugin must
// signal DropChunk so the host does not deliver the still-tokenized original.
func TestStreamWholeChunkDropped(t *testing.T) {
	setSharedVault(newVault(100, time.Hour))
	label := "REDACTED"
	tokenRe := tokenPattern(label)

	req := []byte(`{"model":"drop"}`)
	key := streamKey(req)

	// A chunk that is only the beginning of a token must be fully withheld.
	partial := []byte("<REDACTED_1a2b")
	out, drop := detokenizeStreamChunk(key, partial, tokenRe, []string{label}, nil, getSharedVault(), false)
	if !drop {
		t.Fatalf("expected drop=true when the whole chunk is withheld")
	}
	if len(out) != 0 {
		t.Fatalf("expected no output bytes when dropping, got %q", out)
	}
}

// TestStreamChunkInterceptDropSignaled covers fix #5 end-to-end through the
// core handler: a header-only partial token chunk yields DropChunk=true.
func TestStreamChunkInterceptDropSignaled(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	token := "<REDACTED_1a2b000000000000>"
	activeSnapshot().vault.Put(token, "stream-secret")
	requestBody := []byte(`{"message":"` + token + `"}`)
	streamID := streamKey(requestBody)

	// Header-init resets carry.
	initReq, _ := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:   streamID,
		ChunkIndex:  pluginapi.StreamChunkHeaderInitIndex,
		RequestBody: requestBody,
	})
	if _, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, initReq); err != nil {
		t.Fatalf("stream init error: %v", err)
	}

	chunkReq, _ := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:  streamID,
		ChunkIndex: 0,
		Body:       []byte("<REDACTED_1a2b"),
	})
	raw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, chunkReq)
	if err != nil {
		t.Fatalf("stream chunk error: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	var resp pluginapi.StreamChunkInterceptResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.DropChunk {
		t.Fatalf("expected DropChunk=true for a withheld partial-token chunk, got %+v", resp)
	}
}

// invokeStreamBodyWithID marshals a stream chunk request with an explicit
// RequestID and no per-chunk RequestBody, matching main's schema-5 contract.
func invokeStreamBodyWithID(t *testing.T, sourceFormat, streamID string, index int, body []byte) pluginapi.StreamChunkInterceptResponse {
	t.Helper()
	req, err := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:       streamID,
		SourceFormat:    sourceFormat,
		ResponseHeaders: http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:            body,
		ChunkIndex:      index,
	})
	if err != nil {
		t.Fatalf("marshal stream request: %v", err)
	}
	raw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, req)
	if err != nil {
		t.Fatalf("stream intercept: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("stream intercept failed: %+v", env.Error)
	}
	var response pluginapi.StreamChunkInterceptResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return response
}

func initStreamWithID(t *testing.T, sourceFormat, streamID string, requestBody []byte) {
	t.Helper()
	req := mustJSONMarshal(t, pluginapi.StreamChunkInterceptRequest{
		RequestID:    streamID,
		SourceFormat: sourceFormat,
		RequestBody:  requestBody,
		ChunkIndex:   pluginapi.StreamChunkHeaderInitIndex,
	})
	raw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, req)
	if err != nil {
		t.Fatalf("stream init: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("stream init failed: envelope=%+v err=%v", env, err)
	}
}

func assertNoArgumentState(t *testing.T, key, channelPrefix string) {
	t.Helper()
	streamCarry.mu.Lock()
	defer streamCarry.mu.Unlock()
	entry := streamCarry.entries[key]
	if entry == nil {
		return
	}
	for channel := range entry.arguments {
		if strings.HasPrefix(channel, channelPrefix) {
			t.Fatalf("argument state %q remained after terminal: %#v", channel, entry.arguments)
		}
	}
}

func TestStreamStatefulChatArgumentRestoration(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "mode: filter\n")
	st := activeSnapshot()
	secret := "stateful-chat-tool-argument"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	streamID := "stateful-chat-argument"
	initStreamWithID(t, formatOpenAI, streamID, requestBody)
	t.Cleanup(func() { completeStream(t, streamID) })
	split := len(token) / 2

	firstBody := openAIChatToolArgumentSSEBody(t, 0, 1, `{"value":"`+token[:split], nil)
	first := invokeStreamBodyWithID(t, formatOpenAI, streamID, 0, firstBody)
	secondBody := openAIChatToolArgumentSSEBody(t, 0, 1, token[split:]+`"}`, nil)
	second := invokeStreamBodyWithID(t, formatOpenAI, streamID, 1, secondBody)
	delivered := append(deliveredStreamBody(first, firstBody), deliveredStreamBody(second, secondBody)...)
	argument := openAIChatToolArguments(t, delivered)["0:1"]
	var decoded map[string]string
	if err := json.Unmarshal([]byte(argument), &decoded); err != nil || decoded["value"] != secret {
		t.Fatalf("stateful arguments = %q decoded=%#v err=%v", argument, decoded, err)
	}

	finishBody := openAIChatToolArgumentSSEBody(t, 0, 1, "", "stop")
	_ = invokeStreamBodyWithID(t, formatOpenAI, streamID, 2, finishBody)
	assertNoArgumentState(t, streamID, "argument:openai:")
	end := completeStream(t, streamID)
	if string(end) != "{}" || streamCarry.has(streamID) {
		t.Fatalf("request completion did not cleanly release state: response=%s retained=%v", end, streamCarry.has(streamID))
	}
}

func TestStreamChatArgumentRestorationForNonzeroChoice(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "mode: filter\n")
	st := activeSnapshot()
	secret := "nonzero-choice-chat-tool-argument"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	streamID := "nonzero-choice-chat-argument"
	initStreamWithID(t, formatOpenAI, streamID, requestBody)
	t.Cleanup(func() { completeStream(t, streamID) })
	split := len(token) / 2

	firstBody := openAIChatToolArgumentSSEBody(t, 2, 3, `{"value":"`+token[:split], nil)
	first := invokeStreamBodyWithID(t, formatOpenAI, streamID, 0, firstBody)
	secondBody := openAIChatToolArgumentSSEBody(t, 2, 3, token[split:]+`"}`, nil)
	second := invokeStreamBodyWithID(t, formatOpenAI, streamID, 1, secondBody)
	delivered := append(deliveredStreamBody(first, firstBody), deliveredStreamBody(second, secondBody)...)
	argument := openAIChatToolArguments(t, delivered)["2:3"]
	var decoded map[string]string
	if err := json.Unmarshal([]byte(argument), &decoded); err != nil || decoded["value"] != secret {
		t.Fatalf("nonzero-choice arguments = %q decoded=%#v err=%v", argument, decoded, err)
	}
	finishBody := openAIChatToolArgumentSSEBody(t, 2, 3, "", "stop")
	_ = invokeStreamBodyWithID(t, formatOpenAI, streamID, 2, finishBody)
	assertNoArgumentState(t, streamID, "argument:openai:")
}

func TestToolArgumentRestoresAcrossReconfig(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "mode: filter\n")
	before := activeSnapshot()
	secret := "tool-argument-filter-to-block"
	token := makeToken(before.label, secret)
	before.vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	streamID := "tool-argument-hot-switch"
	initStreamWithID(t, formatOpenAI, streamID, requestBody)
	t.Cleanup(func() { completeStream(t, streamID) })
	split := len(token) / 2

	firstBody := openAIChatToolArgumentSSEBody(t, 0, 0, `{"value":"`+token[:split], nil)
	first := invokeStreamBodyWithID(t, formatOpenAI, streamID, 0, firstBody)
	callRegister(t, pluginabi.MethodPluginReconfigure, "mode: block\n")
	if activeSnapshot().vault != before.vault {
		t.Fatal("hot reconfiguration replaced the live vault")
	}
	secondBody := openAIChatToolArgumentSSEBody(t, 0, 0, token[split:]+`"}`, nil)
	second := invokeStreamBodyWithID(t, formatOpenAI, streamID, 1, secondBody)
	delivered := append(deliveredStreamBody(first, firstBody), deliveredStreamBody(second, secondBody)...)
	argument := openAIChatToolArguments(t, delivered)["0:0"]
	var decoded map[string]string
	if err := json.Unmarshal([]byte(argument), &decoded); err != nil || decoded["value"] != secret {
		t.Fatalf("hot-switch arguments = %q decoded=%#v err=%v", argument, decoded, err)
	}
	finishBody := openAIChatToolArgumentSSEBody(t, 0, 0, "", "stop")
	_ = invokeStreamBodyWithID(t, formatOpenAI, streamID, 2, finishBody)
	assertNoArgumentState(t, streamID, "argument:openai:")
}

func TestArgumentNormalTerminalEndReleasesState(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	token := makeToken(st.label, "normal-terminal-argument")
	st.vault.Put(token, "normal-terminal-argument")
	requestBody := []byte(`{"input":"` + token + `"}`)
	partial := token[:len(token)/2]

	t.Run("Chat finish", func(t *testing.T) {
		resetStreamCarry(requestBody)
		seed := openAIChatToolArgumentSSEBody(t, 0, 0, `{"value":"`+partial, nil)
		_ = invokeStreamBody(t, formatOpenAI, requestBody, 0, seed)
		finish := openAIChatToolArgumentSSEBody(t, 0, 0, "", "stop")
		_ = invokeStreamBody(t, formatOpenAI, requestBody, 1, finish)
		assertNoArgumentState(t, streamKey(requestBody), "argument:openai:")
	})
	t.Run("Responses done and completed", func(t *testing.T) {
		resetStreamCarry(requestBody)
		seedBody := responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", responsesFunctionArgumentDelta(t, 0, "call_done", `{"value":"`+partial))
		_ = invokeStreamBody(t, formatOpenAIResponse, requestBody, 0, seedBody)
		doneBody := responsesFunctionArgumentSSEBody("response.function_call_arguments.done", responsesFunctionArgumentDone(t, 0, "call_done", `{"value":"`+token+`"}`))
		_ = invokeStreamBody(t, formatOpenAIResponse, requestBody, 1, doneBody)
		assertNoArgumentState(t, streamKey(requestBody), "argument:openai-response:")

		seedBody = responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", responsesFunctionArgumentDelta(t, 1, "call_completed", `{"value":"`+partial))
		_ = invokeStreamBody(t, formatOpenAIResponse, requestBody, 2, seedBody)
		completedBody := responsesFunctionArgumentSSEBody("response.completed", mustJSONMarshal(t, map[string]any{"type": "response.completed"}))
		_ = invokeStreamBody(t, formatOpenAIResponse, requestBody, 3, completedBody)
		assertNoArgumentState(t, streamKey(requestBody), "argument:openai-response:")
	})
	t.Run("Claude block and message", func(t *testing.T) {
		resetStreamCarry(requestBody)
		seed := claudeInputJSONDeltaBody(t, 2, `{"value":"`+partial)
		_ = invokeStreamBody(t, formatClaude, requestBody, 0, seed)
		blockStop := claudeSSEBody(t, "content_block_stop", map[string]any{"type": "content_block_stop", "index": 2}, "\n")
		_ = invokeStreamBody(t, formatClaude, requestBody, 1, blockStop)
		assertNoArgumentState(t, streamKey(requestBody), "argument:claude:block:2")

		for i, index := range []int{3, 4} {
			seed = claudeInputJSONDeltaBody(t, index, `{"value":"`+partial)
			_ = invokeStreamBody(t, formatClaude, requestBody, i+2, seed)
		}
		messageStop := claudeSSEBody(t, "message_stop", map[string]any{"type": "message_stop"}, "\n")
		_ = invokeStreamBody(t, formatClaude, requestBody, 4, messageStop)
		assertNoArgumentState(t, streamKey(requestBody), "argument:claude:")
	})
}

func TestArgumentEndWithoutProtocolTerminalCleansState(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	token := makeToken(st.label, "abnormal-end-argument")
	st.vault.Put(token, "abnormal-end-argument")
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	streamID := "argument-abnormal-end"
	initStreamWithID(t, formatOpenAI, streamID, requestBody)
	partial := token[:len(token)/2]
	seedBody := openAIChatToolArgumentSSEBody(t, 0, 0, `{"value":"`+partial, nil)
	seed := invokeStreamBodyWithID(t, formatOpenAI, streamID, 0, seedBody)
	if got := openAIChatToolArguments(t, deliveredStreamBody(seed, seedBody))["0:0"]; got != `{"value":"` {
		t.Fatalf("abnormal-end seed emitted retained suffix: %q", got)
	}
	if !streamCarry.has(streamID) {
		t.Fatal("argument state was not retained before abnormal end")
	}
	end := completeStream(t, streamID)
	if string(end) != "{}" {
		t.Fatalf("request completion attempted to deliver withheld bytes: %s", end)
	}
	if streamCarry.has(streamID) {
		t.Fatal("abnormal end did not remove stream entry")
	}
}

func TestArgumentHardEntryEvictLosesOnlySuffix(t *testing.T) {
	const channel = "argument:openai:choice:0:tool:0"
	label := "REDACTED"
	store := newStreamStore()
	secretA := "evicted-request-secret"
	tokenA := makeToken(label, secretA)
	tokenB := makeToken(label, "other-request-secret")
	v := newVault(2, time.Hour)
	v.Put(tokenA, secretA)
	v.Put(tokenB, "other-request-secret")
	firstKey := "evicted-active-argument"
	store.begin(firstKey)
	split := len(tokenA) / 2
	owner := map[string]any{"arguments": `{"value":"` + tokenA[:split]}
	part := &semanticArgumentPart{frame: &semanticFrame{}, channel: channel, owner: owner, field: "arguments", original: owner["arguments"], text: owner["arguments"].(string)}
	store.rewriteJSONArgumentOps(firstKey, []semanticArgumentOp{{part: part}}, tokenPattern(label), []string{label}, map[string]struct{}{tokenA: {}}, v)
	store.mu.Lock()
	state := store.entries[firstKey].arguments[channel]
	stateCount := len(store.entries[firstKey].arguments)
	store.mu.Unlock()
	if stateCount != 1 || state.tail != tokenA[:split] {
		t.Fatalf("retained state before eviction = %+v count=%d", state, stateCount)
	}
	for i := 0; i < streamCarryMaxEntries; i++ {
		store.begin(fmt.Sprintf("other-active-%d", i))
	}
	if store.has(firstKey) {
		t.Fatal("hard entry pressure did not evict the least-recent active argument")
	}

	otherOwner := map[string]any{"arguments": `{"value":"` + tokenA + `"}`}
	otherPart := &semanticArgumentPart{frame: &semanticFrame{}, channel: channel, owner: otherOwner, field: "arguments", original: otherOwner["arguments"], text: otherOwner["arguments"].(string)}
	store.rewriteJSONArgumentOps("other-request", []semanticArgumentOp{{part: otherPart}}, tokenPattern(label), []string{label}, map[string]struct{}{tokenB: {}}, v)
	if got := otherOwner["arguments"].(string); got != `{"value":"`+tokenA+`"}` || strings.Contains(got, secretA) {
		t.Fatalf("other request crossed restoration gates after eviction: %q", got)
	}
}

func TestArgumentVaultExpirePreservesRepresentation(t *testing.T) {
	label := "REDACTED"
	token := makeToken(label, "expired-between-deltas")
	tokenRe := tokenPattern(label)
	escaped := strings.ReplaceAll(strings.ReplaceAll(token, "<", `\u003c`), ">", `\u003e`)
	for _, tc := range []struct {
		name     string
		argument string
	}{
		{name: "literal", argument: `{"value":"` + token + `"}`},
		{name: "Unicode escaped", argument: `{"value":"` + escaped + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newVault(1, time.Hour)
			v.Put(token, "expired-between-deltas")
			split := strings.Index(tc.argument, "REDACTED") + 4
			first, state := rewriteJSONArgumentFragment(tc.argument[:split], jsonArgumentState{}, tokenRe, []string{label}, map[string]struct{}{token: {}}, v, false)
			v.mu.Lock()
			v.items[token].Value.(*vaultEntry).expiresAt = time.Now().Add(-time.Second)
			v.mu.Unlock()
			second, state := rewriteJSONArgumentFragment(tc.argument[split:], state, tokenRe, []string{label}, map[string]struct{}{token: {}}, v, true)
			if state.tail != "" || first+second != tc.argument {
				t.Fatalf("expired %s representation changed: got %q want %q state=%+v", tc.name, first+second, tc.argument, state)
			}
		})
	}
}

func TestArgumentProtocolsRemainOnePass(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	innerToken := makeToken(st.label, "one-pass-inner")
	outerSecret := "contains " + innerToken
	outerToken := makeToken(st.label, outerSecret)
	st.vault.Put(innerToken, "one-pass-inner")
	st.vault.Put(outerToken, outerSecret)
	requestBody := []byte(`{"input":"` + outerToken + ` ` + innerToken + `"}`)
	split := len(outerToken) / 2

	tests := []struct {
		name     string
		first    func() []byte
		second   func() []byte
		format   string
		argument func([]byte) string
	}{
		{name: "Chat", format: formatOpenAI,
			first:    func() []byte { return openAIChatToolArgumentSSEBody(t, 0, 0, `{"value":"`+outerToken[:split], nil) },
			second:   func() []byte { return openAIChatToolArgumentSSEBody(t, 0, 0, outerToken[split:]+`"}`, nil) },
			argument: func(body []byte) string { return openAIChatToolArguments(t, body)["0:0"] }},
		{name: "Responses", format: formatOpenAIResponse,
			first: func() []byte {
				return responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", responsesFunctionArgumentDelta(t, 0, "call_one_pass", `{"value":"`+outerToken[:split]))
			},
			second: func() []byte {
				return responsesFunctionArgumentSSEBody("response.function_call_arguments.delta", responsesFunctionArgumentDelta(t, 0, "call_one_pass", outerToken[split:]+`"}`))
			},
			argument: func(body []byte) string { return openAIResponsesFunctionArgumentDeltas(t, body)["0:call_one_pass"] }},
		{name: "Claude", format: formatClaude,
			first:    func() []byte { return claudeInputJSONDeltaBody(t, 0, `{"value":"`+outerToken[:split]) },
			second:   func() []byte { return claudeInputJSONDeltaBody(t, 0, outerToken[split:]+`"}`) },
			argument: func(body []byte) string { return claudeInputJSONByBlock(t, body)[0] }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetStreamCarry(requestBody)
			firstBody := tc.first()
			first := invokeStreamBody(t, tc.format, requestBody, 0, firstBody)
			secondBody := tc.second()
			second := invokeStreamBody(t, tc.format, requestBody, 1, secondBody)
			delivered := append(deliveredStreamBody(first, firstBody), deliveredStreamBody(second, secondBody)...)
			argument := tc.argument(delivered)
			var decoded map[string]string
			if err := json.Unmarshal([]byte(argument), &decoded); err != nil || decoded["value"] != outerSecret {
				t.Fatalf("%s one-pass argument = %q decoded=%#v err=%v", tc.name, argument, decoded, err)
			}
			if decoded["value"] == "contains one-pass-inner" {
				t.Fatalf("%s recursively restored nested token: %q", tc.name, decoded["value"])
			}
		})
	}
}

// TestStreamRestoresByRequestID covers the streaming-performance fix: a
// stateful stream caches its per-request token allowlist at the header-init call
// (keyed by RequestID) so payload chunks that carry only RequestID and no
// RequestBody still restore tokens. This lets the host stop re-sending and the
// plugin stop re-hashing/re-scanning the full request body on every chunk.
func TestStreamRestoresByRequestID(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	secret := "sk-streamid-secret-value"
	token := makeToken("REDACTED", secret)
	activeSnapshot().vault.Put(token, secret)
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	streamID := "stream-stateful-1"

	// Header-init carries the heavy RequestBody once; subsequent chunks do not.
	initReq, _ := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:   streamID,
		ChunkIndex:  pluginapi.StreamChunkHeaderInitIndex,
		RequestBody: requestBody,
	})
	if _, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, initReq); err != nil {
		t.Fatalf("stream init error: %v", err)
	}
	t.Cleanup(func() {
		completeStream(t, streamID)
		if streamCarry.has(streamID) {
			t.Errorf("stream cleanup did not release state for %q", streamID)
		}
	})

	chunk := []byte("data: {\"choices\":[{\"delta\":{\"content\":\"" + token + "\"}}]}\n\n")
	resp := invokeStreamBodyWithID(t, formatOpenAI, streamID, 0, chunk)
	delivered := deliveredStreamBody(resp, chunk)
	if !bytes.Contains(delivered, []byte(secret)) {
		t.Fatalf("stream chunk must restore the secret from RequestID-cached state; got %q", delivered)
	}
	if bytes.Contains(delivered, []byte(token)) {
		t.Fatalf("delivered chunk still contains the token, restoration did not run: %q", delivered)
	}
}

func TestStreamRequestCompletionReleasesState(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	streamID := "stream-stateful-end"
	initReq, _ := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:   streamID,
		ChunkIndex:  pluginapi.StreamChunkHeaderInitIndex,
		RequestBody: []byte(`{"messages":[]}`),
	})
	if _, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, initReq); err != nil {
		t.Fatalf("stream init error: %v", err)
	}
	if !streamCarry.has(streamID) {
		t.Fatal("stream init did not retain state")
	}

	completeStream(t, streamID)
	if streamCarry.has(streamID) {
		t.Fatal("stream end did not release state")
	}
}

func TestStreamStatefulRepeatedInitReplacesAbandonedAttempt(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	firstSecret := "stateful-first-attempt-secret"
	secondSecret := "stateful-second-attempt-secret"
	firstToken := makeToken(st.label, firstSecret)
	secondToken := makeToken(st.label, secondSecret)
	st.vault.Put(firstToken, firstSecret)
	st.vault.Put(secondToken, secondSecret)
	streamID := "stream-stateful-retry"

	initStreamWithID(t, formatOpenAI, streamID, []byte(`{"messages":[{"content":"`+firstToken+`"}]}`))
	streamCarry.mu.Lock()
	entry := streamCarry.entries[streamID]
	entry.carry = []byte("abandoned-carry")
	entry.content = map[string]string{"abandoned-content": "value"}
	entry.arguments = map[string]jsonArgumentState{"abandoned-argument": {tail: "value"}}
	entry.argumentOverflow = true
	streamCarry.mu.Unlock()

	initStreamWithID(t, formatOpenAI, streamID, []byte(`{"messages":[{"content":"`+secondToken+`"}]}`))
	streamCarry.mu.Lock()
	entry = streamCarry.entries[streamID]
	if entry == nil || !entry.active {
		streamCarry.mu.Unlock()
		t.Fatal("repeated stream init did not create active replacement state")
	}
	_, hasFirst := entry.allowed[firstToken]
	_, hasSecond := entry.allowed[secondToken]
	staleState := len(entry.carry) != 0 || len(entry.content) != 0 || len(entry.arguments) != 0 || entry.argumentOverflow
	streamCarry.mu.Unlock()
	if hasFirst || !hasSecond {
		t.Fatalf("replacement allowlist hasFirst=%v hasSecond=%v", hasFirst, hasSecond)
	}
	if staleState {
		t.Fatal("repeated stream init retained carry or semantic state from abandoned attempt")
	}

	firstBody := []byte(`data: {"delta":"` + firstToken + `"}` + "\n\n")
	first := invokeStreamBodyWithID(t, formatOpenAI, streamID, 0, firstBody)
	firstDelivered := deliveredStreamBody(first, firstBody)
	if bytes.Contains(firstDelivered, []byte(firstSecret)) || !bytes.Contains(firstDelivered, []byte(firstToken)) {
		t.Fatalf("abandoned allowlist remained usable: %q", firstDelivered)
	}
	secondBody := []byte(`data: {"delta":"` + secondToken + `"}` + "\n\n")
	second := invokeStreamBodyWithID(t, formatOpenAI, streamID, 1, secondBody)
	secondDelivered := deliveredStreamBody(second, secondBody)
	if !bytes.Contains(secondDelivered, []byte(secondSecret)) || bytes.Contains(secondDelivered, []byte(secondToken)) {
		t.Fatalf("replacement allowlist was not used: %q", secondDelivered)
	}
}

func TestStreamRequestCompletionIsIdempotentAndDropsRetainedSuffix(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	streamID := "stream-stateful-repeated-end"
	initStreamWithID(t, formatOpenAI, streamID, []byte(`{"messages":[]}`))
	if !streamCarry.setCarry(streamID, []byte("withheld-secret-suffix")) {
		t.Fatal("could not stage retained stream suffix")
	}

	for i := 0; i < 2; i++ {
		response := completeStream(t, streamID)
		if string(response) != "{}" {
			t.Fatalf("completion call %d emitted retained state: %s", i+1, response)
		}
		if streamCarry.has(streamID) {
			t.Fatalf("end call %d retained stream state", i+1)
		}
	}
}

// TestVaultExpiryPurgedByLen covers fix #8: expired entries are purged even when
// never accessed by Get, so plaintext does not linger and Len reflects reality.
func TestVaultExpiryPurgedByLen(t *testing.T) {
	v := newVault(10, 20*time.Millisecond)
	v.Put("<REDACTED_1111111111111111>", "one")
	v.Put("<REDACTED_2222222222222222>", "two")
	if v.Len() != 2 {
		t.Fatalf("expected len 2, got %d", v.Len())
	}
	time.Sleep(40 * time.Millisecond)
	if got := v.Len(); got != 0 {
		t.Fatalf("expected expired entries purged, len=%d", got)
	}
}

// TestVaultReconfigurePreservesInFlight covers fix #11: reconfiguring the plugin
// must not drop token mappings for requests already in flight.
func TestVaultReconfigurePreservesInFlight(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	label := "REDACTED"
	secret := "sk-inflight000000000000"
	token := makeToken(label, secret)
	getSharedVault().Put(token, secret)

	// Reconfigure keeps the same label so the token shape is unchanged.
	callRegister(t, pluginabi.MethodPluginReconfigure, "vault_max_entries: 50\n")

	if got, ok := getSharedVault().Get(token); !ok || got != secret {
		t.Fatalf("in-flight mapping lost across reconfigure: got=%q ok=%v", got, ok)
	}
}

func TestReconfigureLabelChangeRestoresOldToken(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "token_label: OLD\n")
	secret := "sk-old-label000000000000"
	token := makeToken("OLD", secret)
	getSharedVault().Put(token, secret)

	callRegister(t, pluginabi.MethodPluginReconfigure, "token_label: NEW\n")
	requestBody := []byte(`{"prompt":"` + token + `"}`)
	responseBody := []byte(`{"answer":"` + token + `"}`)
	req, _ := json.Marshal(pluginapi.ResponseInterceptRequest{RequestBody: requestBody, Body: responseBody})
	raw, err := handleMethod(pluginabi.MethodResponseInterceptAfter, req)
	if err != nil {
		t.Fatalf("response intercept: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	var resp pluginapi.ResponseInterceptResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !strings.Contains(string(resp.Body), secret) {
		t.Fatalf("old-label token was not restored: %s", resp.Body)
	}
}

func TestReconfigureSharesVaultWithOldSnapshotWriter(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "token_label: OLD\n")
	old := activeSnapshot()
	callRegister(t, pluginabi.MethodPluginReconfigure, "token_label: NEW\n")

	secret := "sk-late-write00000000000"
	token := newRedactFunc(old.label, old.vault)(secret)
	current := activeSnapshot()
	if current.vault != old.vault {
		t.Fatal("reconfigure must reuse the vault shared with in-flight snapshots")
	}
	allowed := collectTokens([]byte(token), current.restoreTokenRe, current.vault)
	restored := restoreBody([]byte(token), current.restoreTokenRe, allowed, current.vault)
	if string(restored) != secret {
		t.Fatalf("late old-snapshot write was not restorable: %q", restored)
	}
}

func TestReconfigureOldLabelSplitStreamRestores(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "token_label: OLD\n")
	secret := "sk-old-stream00000000000"
	token := makeToken("OLD", secret)
	getSharedVault().Put(token, secret)
	callRegister(t, pluginabi.MethodPluginReconfigure, "token_label: NEW\n")
	requestBody := []byte(`{"messages":[{"content":"` + token + `"}]}`)
	streamID := streamKey(requestBody)
	initStreamWithID(t, formatOpenAI, streamID, requestBody)

	half := len(token) / 2
	firstReq, _ := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:  streamID,
		Body:       []byte(token[:half]),
		ChunkIndex: 0,
	})
	firstRaw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, firstReq)
	if err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	var firstEnv envelope
	if err := json.Unmarshal(firstRaw, &firstEnv); err != nil {
		t.Fatalf("unmarshal first envelope: %v", err)
	}
	var first pluginapi.StreamChunkInterceptResponse
	if err := json.Unmarshal(firstEnv.Result, &first); err != nil {
		t.Fatalf("unmarshal first response: %v", err)
	}
	if !first.DropChunk {
		t.Fatalf("old-label partial token was not withheld: %+v", first)
	}

	secondReq, _ := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:  streamID,
		Body:       []byte(token[half:]),
		ChunkIndex: 1,
	})
	secondRaw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, secondReq)
	if err != nil {
		t.Fatalf("second chunk: %v", err)
	}
	var secondEnv envelope
	if err := json.Unmarshal(secondRaw, &secondEnv); err != nil {
		t.Fatalf("unmarshal second envelope: %v", err)
	}
	var second pluginapi.StreamChunkInterceptResponse
	if err := json.Unmarshal(secondEnv.Result, &second); err != nil {
		t.Fatalf("unmarshal second response: %v", err)
	}
	if string(second.Body) != secret {
		t.Fatalf("old-label split token was not restored: %q", second.Body)
	}
}

// TestResponsesRealExecutorFramingEmitsText reproduces the real executor
// stream framing for the openai-response protocol: each translator event is
// delivered as its OWN chunk with NO trailing newline, and the blank SSE
// dispatch separator ("\n\n") is added AFTER interception at write time, so it
// is NEVER delivered to the plugin as a chunk.
//
// If the plugin withholds a complete Responses event waiting for a blank
// separator that never arrives, every chunk is dropped and the user sees an
// empty response.
func TestResponsesRealExecutorFramingEmitsText(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "real-framing-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)

	// Header-init call.
	invokeStreamBody(t, formatOpenAIResponse, requestBody, pluginapi.StreamChunkHeaderInitIndex, nil)

	// Realistic multi-event sequence as delivered by the executor: each event
	// is a separate chunk shaped like SSEEventData => "event: X\ndata: {json}"
	// with NO trailing newline. No separator chunk is ever delivered.
	deltaPayload, ok := encodeSemanticJSON(map[string]any{
		"type":          "response.output_text.delta",
		"output_index":  0,
		"content_index": 0,
		"delta":         token,
	})
	if !ok {
		t.Fatal("encode delta")
	}
	createdPayload, ok := encodeSemanticJSON(map[string]any{
		"type":     "response.created",
		"response": map[string]any{"id": "resp-1"},
	})
	if !ok {
		t.Fatal("encode created")
	}

	chunks := [][]byte{
		[]byte("event: response.created\ndata: " + string(createdPayload)),
		[]byte("event: response.output_text.delta\ndata: " + string(deltaPayload)),
	}

	var restored string
	for i, chunk := range chunks {
		resp := invokeStreamBody(t, formatOpenAIResponse, requestBody, i, chunk)
		delivered := deliveredStreamBody(resp, chunk)
		if len(delivered) > 0 {
			restored += openAIResponsesStreamText(t, delivered)
		}
	}

	if restored != secret {
		t.Fatalf("expected restored secret %q, got %q (empty response bug)", secret, restored)
	}
}

// TestResponsesSplitTokenAcrossDeltasFromCapture reproduces a REAL captured
// Codex->Responses stream where the model echoed the placeholder token back and
// the token was split across ~17 separate output_text.delta events (one per
// chunk): " `<", "RE", "DA", "CT", "ED", "_f", "3", "cc", ... ">`". Each event
// arrives as its own data-only chunk (codex passthrough: event line stripped,
// no trailing newline, no separator chunk). The detokenizer must reassemble the
// split token across chunks and emit the restored secret; if it withholds the
// tail forever nothing is emitted and the user sees an empty response.
func TestResponsesSplitTokenAcrossDeltasFromCapture(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "test-secret-value"
	// The exact placeholder observed in the capture.
	token := "<" + st.label + "_f3ccfd095a4bb0f7>"
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)

	invokeStreamBody(t, formatOpenAIResponse, requestBody, pluginapi.StreamChunkHeaderInitIndex, nil)

	// Deltas exactly as captured (seq 4..35). The token spans seq 10..26.
	deltas := []string{
		"我", "只能", "看到", "占", "位", "符",
		" `<", "RE", "DA", "CT", "ED", "_f", "3", "cc", "fd", "095", "a", "4", "bb", "0", "f", "7", ">`",
		"，", "看", "不到", "原", "始", "测试", "密", "钥", "。",
	}

	// Expected restored plaintext: the placeholder replaced by the secret.
	want := "我只能看到占位符 `" + secret + "`，看不到原始测试密钥。"

	var chunks [][]byte
	created, ok := encodeSemanticJSON(map[string]any{
		"type":     "response.created",
		"response": map[string]any{"id": "resp-1"},
	})
	if !ok {
		t.Fatal("encode created")
	}
	// The codex executor scans the upstream SSE body line by line with a
	// bufio.Scanner (newline stripped) and emits EACH line as its own chunk.
	// The blank separator line becomes an empty payload the host skips. So the
	// plugin receives every event as TWO separate chunks: the "event:" line
	// alone, then the "data:" line alone, both with no trailing newline.
	appendEvent := func(eventType string, payload []byte) {
		chunks = append(chunks, []byte("event: "+eventType))
		chunks = append(chunks, []byte("data: "+string(payload)))
	}
	appendEvent("response.created", created)
	for i, d := range deltas {
		payload, okEnc := encodeSemanticJSON(map[string]any{
			"type":            "response.output_text.delta",
			"output_index":    0,
			"content_index":   0,
			"item_id":         "msg-1",
			"delta":           d,
			"sequence_number": i + 4,
		})
		if !okEnc {
			t.Fatal("encode delta")
		}
		appendEvent("response.output_text.delta", payload)
	}

	var restored string
	for i, chunk := range chunks {
		resp := invokeStreamBody(t, formatOpenAIResponse, requestBody, i, chunk)
		delivered := deliveredStreamBody(resp, chunk)
		if len(delivered) > 0 {
			restored += openAIResponsesStreamText(t, delivered)
		}
	}

	if restored != want {
		t.Fatalf("expected restored %q, got %q (empty/broken response bug)", want, restored)
	}
}

// TestResponsesNormalTextEmittedWhenRequestHadToken reproduces the ACTUAL
// production path: the request contained a redacted secret (so the token is in
// the request body and the stream fast-path gate activates full detokenization
// for every chunk), but the model's streamed reply is ordinary text that
// contains NO token. Every chunk must still be emitted verbatim; nothing may be
// withheld or dropped, or the user sees an empty response.
func TestResponsesNormalTextEmittedWhenRequestHadToken(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "request-side-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	// The request carried the token (as it would after request redaction).
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)

	invokeStreamBody(t, formatOpenAIResponse, requestBody, pluginapi.StreamChunkHeaderInitIndex, nil)

	// The model reply is normal words, streamed one delta per chunk, NO token.
	words := []string{"Hello", " there", " friend"}
	var want string
	var chunks [][]byte
	created, ok := encodeSemanticJSON(map[string]any{
		"type":     "response.created",
		"response": map[string]any{"id": "resp-1"},
	})
	if !ok {
		t.Fatal("encode created")
	}
	chunks = append(chunks, []byte("event: response.created\ndata: "+string(created)))
	for _, w := range words {
		want += w
		payload, okEnc := encodeSemanticJSON(map[string]any{
			"type":          "response.output_text.delta",
			"output_index":  0,
			"content_index": 0,
			"delta":         w,
		})
		if !okEnc {
			t.Fatal("encode delta")
		}
		chunks = append(chunks, []byte("event: response.output_text.delta\ndata: "+string(payload)))
	}

	var restored string
	for i, chunk := range chunks {
		resp := invokeStreamBody(t, formatOpenAIResponse, requestBody, i, chunk)
		delivered := deliveredStreamBody(resp, chunk)
		if len(delivered) > 0 {
			restored += openAIResponsesStreamText(t, delivered)
		}
	}

	if restored != want {
		t.Fatalf("expected normal reply %q, got %q (empty response bug)", want, restored)
	}
}

// TestResponsesDataOnlyFramingEmitsText reproduces the openai_compat
// passthrough framing for a native OpenAI Responses upstream: the executor
// strips the "event:" line and forwards ONLY the trimmed "data: {json}" line
// as its own chunk, with NO trailing newline and NO separator chunk.
//
// This is the most production-relevant shape for a native Responses upstream.
func TestResponsesDataOnlyFramingEmitsText(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	secret := "data-only-secret"
	token := makeToken(st.label, secret)
	st.vault.Put(token, secret)
	requestBody := []byte(`{"input":"` + token + `"}`)
	resetStreamCarry(requestBody)

	invokeStreamBody(t, formatOpenAIResponse, requestBody, pluginapi.StreamChunkHeaderInitIndex, nil)

	deltaPayload, ok := encodeSemanticJSON(map[string]any{
		"type":          "response.output_text.delta",
		"output_index":  0,
		"content_index": 0,
		"delta":         token,
	})
	if !ok {
		t.Fatal("encode delta")
	}
	createdPayload, ok := encodeSemanticJSON(map[string]any{
		"type":     "response.created",
		"response": map[string]any{"id": "resp-1"},
	})
	if !ok {
		t.Fatal("encode created")
	}

	// openai_compat framing: event line stripped, data line trimmed, one event
	// per chunk, no trailing newline, no separator chunk.
	chunks := [][]byte{
		[]byte("data: " + string(createdPayload)),
		[]byte("data: " + string(deltaPayload)),
	}

	var restored string
	for i, chunk := range chunks {
		resp := invokeStreamBody(t, formatOpenAIResponse, requestBody, i, chunk)
		delivered := deliveredStreamBody(resp, chunk)
		if len(delivered) > 0 {
			restored += openAIResponsesStreamText(t, delivered)
		}
	}

	if restored != secret {
		t.Fatalf("expected restored secret %q, got %q (empty response bug)", secret, restored)
	}
}
