package main

import (
	"encoding/json"
	"fmt"
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

func benchInvokeChunk(b *testing.B, requestBody, chunk []byte, index int) {
	b.Helper()
	req, err := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		SourceFormat:    formatOpenAI,
		RequestBody:     requestBody,
		ResponseHeaders: http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:            chunk,
		ChunkIndex:      index,
	})
	if err != nil {
		b.Fatalf("marshal: %v", err)
	}
	if _, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, req); err != nil {
		b.Fatalf("handleMethod: %v", err)
	}
}

func benchInvokeStatefulChunk(b *testing.B, streamID string, chunk []byte, index int) {
	b.Helper()
	req, err := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		StreamID:        streamID,
		SourceFormat:    formatOpenAI,
		ResponseHeaders: http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:            chunk,
		ChunkIndex:      index,
	})
	if err != nil {
		b.Fatalf("marshal: %v", err)
	}
	if _, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, req); err != nil {
		b.Fatalf("handleMethod: %v", err)
	}
}

// BenchmarkStreamChunkPerBodySize measures the full plugin-side per-chunk cost
// (json.Unmarshal + early-out regex scan + streamKey sha256 + detokenize) as the
// request body size grows while the delivered chunk stays tiny. If per-chunk
// cost scales with body size, the O(bodySize) work per chunk is confirmed.
func BenchmarkStreamChunkPerBodySize(b *testing.B) {
	for _, size := range []int{1 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("body=%dKiB", size>>10), func(b *testing.B) {
			label, _ := detokTestSetup()
			requestBody, token := benchStreamRequestBody(b, label, size)
			chunk := benchOpenAIChunk(token)
			// Warm the legacy payload path so the timed loop measures steady-state
			// per-chunk cost after the request-scoped allowlist has been cached.
			resetStreamCarry(requestBody)
			benchInvokeChunk(b, requestBody, chunk, 0)
			b.SetBytes(int64(len(requestBody)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchInvokeChunk(b, requestBody, chunk, i+1)
			}
			b.StopTimer()
			resetStreamCarry(requestBody)
		})
	}
}

// BenchmarkStreamChunkStateful measures the optimized path: the 1 MiB request
// body is processed once at header init, then each payload chunk carries only a
// stable StreamID and the small response body.
func BenchmarkStreamChunkStateful(b *testing.B) {
	label, _ := detokTestSetup()
	requestBody, token := benchStreamRequestBody(b, label, 1<<20)
	chunk := benchOpenAIChunk(token)
	streamID := "benchmark-stateful-stream"
	initRequest, err := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		StreamID:    streamID,
		RequestBody: requestBody,
		ChunkIndex:  pluginapi.StreamChunkHeaderInitIndex,
	})
	if err != nil {
		b.Fatalf("marshal init: %v", err)
	}
	if _, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, initRequest); err != nil {
		b.Fatalf("init stream: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchInvokeStatefulChunk(b, streamID, chunk, i)
	}
	b.StopTimer()
	benchInvokeStatefulChunk(b, streamID, nil, pluginapi.StreamChunkEndIndex)
}

// BenchmarkStreamChunkComponents isolates the three O(bodySize) costs that run
// per chunk so we can attribute the linear slowdown: (1) json.Unmarshal of the
// full StreamChunkInterceptRequest (forced by the host sending RequestBody every
// chunk), (2) streamKey sha256 over the full body, (3) the early-out
// tokenRe.Find regex scan over the full body.
func BenchmarkStreamChunkComponents(b *testing.B) {
	for _, size := range []int{64 << 10, 1 << 20} {
		label, tokenRe := detokTestSetup()
		requestBody, token := benchStreamRequestBody(b, label, size)
		chunk := benchOpenAIChunk(token)
		reqBytes, err := json.Marshal(pluginapi.StreamChunkInterceptRequest{
			SourceFormat:    formatOpenAI,
			RequestBody:     requestBody,
			ResponseHeaders: http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:            chunk,
			ChunkIndex:      1,
		})
		if err != nil {
			b.Fatalf("marshal: %v", err)
		}

		b.Run(fmt.Sprintf("unmarshal/body=%dKiB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(len(requestBody)))
			for i := 0; i < b.N; i++ {
				var req pluginapi.StreamChunkInterceptRequest
				if err := json.Unmarshal(reqBytes, &req); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("streamKey/body=%dKiB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(len(requestBody)))
			for i := 0; i < b.N; i++ {
				_ = streamKey(requestBody)
			}
		})

		b.Run(fmt.Sprintf("regexFind/body=%dKiB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(len(requestBody)))
			for i := 0; i < b.N; i++ {
				_ = tokenRe.Find(requestBody)
			}
		})
	}
}
