package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// benchStreamRequestBody builds a realistic request body of approximately
// sizeBytes that contains exactly one real token (so the early-out check does
// not short-circuit and the full per-chunk path runs).
func benchStreamRequestBody(b *testing.B, label string, sizeBytes int) ([]byte, string) {
	b.Helper()
	original := "sk-secretvalue-abcdefghijklmnop"
	token := makeToken(label, original)
	getSharedVault().Put(token, original)
	// Pad the request body with filler so it reaches the target size. The token
	// sits near the end so tokenRe.Find still has to scan.
	var sb strings.Builder
	filler := strings.Repeat("a", 1024)
	for sb.Len() < sizeBytes {
		sb.WriteString(filler)
	}
	body := `{"messages":[{"role":"user","content":"` + sb.String() + " " + token + `"}]}`
	return []byte(body), token
}

// benchOpenAIChunk builds a small SSE chunk carrying the token in an OpenAI
// streaming delta, i.e. the realistic "few characters at a time" case.
func benchOpenAIChunk(token string) []byte {
	frame := `{"choices":[{"delta":{"content":"` + token + `"},"index":0}]}`
	return []byte("data: " + frame + "\n\n")
}

func benchInvokeStatefulChunk(b *testing.B, streamID string, chunk []byte, index int) {
	b.Helper()
	req, err := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:       streamID,
		SourceFormat:    formatOpenAI,
		ResponseHeaders: http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:            chunk,
		ChunkIndex:      index,
	})
	if err != nil {
		b.Fatalf("marshal: %v", err)
	}
	raw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, req)
	if err != nil {
		b.Fatalf("handleMethod: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		b.Fatalf("stream chunk failed: envelope=%+v err=%v", env, err)
	}
}

// BenchmarkStreamChunkStateful measures the schema-v5 path: the 1 MiB request
// body is processed once at header init, then each payload chunk carries only a
// stable RequestID and the small response body.
func BenchmarkStreamChunkStateful(b *testing.B) {
	label, _ := detokTestSetup()
	requestBody, token := benchStreamRequestBody(b, label, 1<<20)
	chunk := benchOpenAIChunk(token)
	streamID := "benchmark-stateful-stream"
	streamCarry.reset(streamID)
	initRequest, err := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:   streamID,
		RequestBody: requestBody,
		ChunkIndex:  pluginapi.StreamChunkHeaderInitIndex,
	})
	if err != nil {
		b.Fatalf("marshal init: %v", err)
	}
	raw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, initRequest)
	if err != nil {
		b.Fatalf("init stream: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		b.Fatalf("stream init failed: envelope=%+v err=%v", env, err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchInvokeStatefulChunk(b, streamID, chunk, i)
	}
	b.StopTimer()
	completeStream(b, streamID)
}
