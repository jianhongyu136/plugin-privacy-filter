package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSemanticOpenAIChatPreservesEventLineAndCRLF(t *testing.T) {
	setSharedVault(newVault(16, time.Hour))
	label := "REDACTED"
	secret := "semantic-crlf-secret"
	token := makeToken(label, secret)
	getSharedVault().Put(token, secret)
	allowed := collectTokens([]byte(token), restoreTokenPattern(), getSharedVault())
	body := []byte("event: message\r\ndata: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"" + token + "\"}}]}\r\n\r\n")

	out, handled := restoreSemanticStream("semantic-crlf", body, restoreTokenPattern(), []string{label}, allowed, getSharedVault(), "text/event-stream", formatOpenAI)
	if !handled || !bytes.Contains(out, []byte("event: message\r\n")) || !bytes.Contains(out, []byte(secret)) || !bytes.HasSuffix(out, []byte("\r\n\r\n")) {
		t.Fatalf("semantic SSE frame was not preserved: handled=%v out=%q", handled, out)
	}
}

func TestSemanticStreamRequiresMatchingSourceFormat(t *testing.T) {
	tests := []struct {
		name         string
		body         []byte
		sourceFormat string
	}{
		{
			name:         "OpenAI shape under Claude",
			body:         []byte("data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"plain\"}}]}\n\n"),
			sourceFormat: formatClaude,
		},
		{
			name:         "Gemini bare JSON shape under Claude",
			body:         []byte(`{"candidates":[{"index":0,"content":{"parts":[{"text":"plain"}]}}]}`),
			sourceFormat: formatClaude,
		},
		{
			name:         "Gemini SSE shape under OpenAI",
			body:         []byte("data: {\"candidates\":[{\"index\":0,\"content\":{\"parts\":[{\"text\":\"plain\"}]}}]}\n\n"),
			sourceFormat: formatOpenAI,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, handled := restoreSemanticStream("wrong-format", tt.body, restoreTokenPattern(), nil, nil, getSharedVault(), "text/event-stream", tt.sourceFormat); handled {
				t.Fatalf("body shape activated under source format %q", tt.sourceFormat)
			}
		})
	}
}

func TestSemanticAdaptersRejectInvalidRequiredIndices(t *testing.T) {
	chatDoc := func(index any, includeIndex bool) map[string]any {
		choice := map[string]any{"delta": map[string]any{"content": "<REDACTED_1"}}
		if includeIndex {
			choice["index"] = index
		}
		return map[string]any{
			"object":  "chat.completion.chunk",
			"choices": []any{choice},
		}
	}
	responsesDoc := func(outputIndex, contentIndex any, includeOutput, includeContent bool) map[string]any {
		doc := map[string]any{
			"type":    "response.output_text.delta",
			"item_id": "msg_invalid",
			"delta":   "<REDACTED_1",
		}
		if includeOutput {
			doc["output_index"] = outputIndex
		}
		if includeContent {
			doc["content_index"] = contentIndex
		}
		return doc
	}
	claudeDoc := func(index any, includeIndex bool) map[string]any {
		doc := map[string]any{
			"type":  "content_block_delta",
			"delta": map[string]any{"type": "text_delta", "text": "<REDACTED_1"},
		}
		if includeIndex {
			doc["index"] = index
		}
		return doc
	}
	geminiDoc := func(index any, includeIndex bool) map[string]any {
		candidate := map[string]any{
			"content": map[string]any{"parts": []any{map[string]any{"text": "<REDACTED_1"}}},
		}
		if includeIndex {
			candidate["index"] = index
		}
		return map[string]any{"candidates": []any{candidate}}
	}
	groupsForSSE := func(t *testing.T, sourceFormat string, doc map[string]any) int {
		t.Helper()
		payload, ok := encodeSemanticJSON(doc)
		if !ok {
			t.Fatal("encode semantic test event")
		}
		body := append([]byte("data: "), payload...)
		body = append(body, '\n', '\n')
		switch sourceFormat {
		case formatOpenAIResponse:
			batch, _ := parseOpenAIResponsesSemantic(body)
			return len(batch.groups)
		case formatClaude:
			batch, _ := parseClaudeSemantic(body)
			return len(batch.groups)
		default:
			t.Fatalf("unsupported semantic test source format %q", sourceFormat)
			return -1
		}
	}

	tests := []struct {
		name   string
		groups func(*testing.T) int
	}{
		{name: "OpenAI Chat missing", groups: func(*testing.T) int {
			return len(parseOpenAIChatSemantic([]*semanticFrame{{doc: chatDoc(nil, false)}}).groups)
		}},
		{name: "OpenAI Chat negative", groups: func(*testing.T) int {
			return len(parseOpenAIChatSemantic([]*semanticFrame{{doc: chatDoc(json.Number("-1"), true)}}).groups)
		}},
		{name: "OpenAI Chat fractional", groups: func(*testing.T) int {
			return len(parseOpenAIChatSemantic([]*semanticFrame{{doc: chatDoc(json.Number("0.5"), true)}}).groups)
		}},
		{name: "Responses missing output", groups: func(t *testing.T) int {
			return groupsForSSE(t, formatOpenAIResponse, responsesDoc(nil, 0, false, true))
		}},
		{name: "Responses negative output", groups: func(t *testing.T) int {
			return groupsForSSE(t, formatOpenAIResponse, responsesDoc(-1, 0, true, true))
		}},
		{name: "Responses missing content", groups: func(t *testing.T) int {
			return groupsForSSE(t, formatOpenAIResponse, responsesDoc(0, nil, true, false))
		}},
		{name: "Responses negative content", groups: func(t *testing.T) int {
			return groupsForSSE(t, formatOpenAIResponse, responsesDoc(0, -1, true, true))
		}},
		{name: "Responses fractional", groups: func(t *testing.T) int {
			return groupsForSSE(t, formatOpenAIResponse, responsesDoc(0.5, 0, true, true))
		}},
		{name: "Claude missing", groups: func(t *testing.T) int {
			return groupsForSSE(t, formatClaude, claudeDoc(nil, false))
		}},
		{name: "Claude negative", groups: func(t *testing.T) int {
			return groupsForSSE(t, formatClaude, claudeDoc(-1, true))
		}},
		{name: "Claude fractional", groups: func(t *testing.T) int {
			return groupsForSSE(t, formatClaude, claudeDoc(0.5, true))
		}},
		{name: "Gemini negative", groups: func(*testing.T) int {
			batch, _ := parseGeminiFrames([]*semanticFrame{{doc: geminiDoc(json.Number("-1"), true)}})
			return len(batch.groups)
		}},
		{name: "Gemini fractional", groups: func(*testing.T) int {
			batch, _ := parseGeminiFrames([]*semanticFrame{{doc: geminiDoc(json.Number("0.5"), true)}})
			return len(batch.groups)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.groups(t); got != 0 {
				t.Fatalf("invalid index admitted %d semantic channel(s)", got)
			}
		})
	}

	t.Run("Gemini missing candidate index uses array position", func(t *testing.T) {
		batch, _ := parseGeminiFrames([]*semanticFrame{{doc: geminiDoc(nil, false)}})
		if _, ok := batch.groups["gemini:candidate:0:part:0"]; !ok || len(batch.groups) != 1 {
			t.Fatalf("Gemini array-position fallback was not admitted: %#v", batch.groups)
		}
	})
}

func TestSemanticOpenAIChatPendingEmptyDeltaPreservesFrame(t *testing.T) {
	setSharedVault(newVault(16, time.Hour))
	label := "REDACTED"
	secret := "pending-empty-secret"
	token := makeToken(label, secret)
	getSharedVault().Put(token, secret)
	allowed := collectTokens([]byte(token), restoreTokenPattern(), getSharedVault())
	key := "semantic-pending-empty"
	streamCarry.reset(key)
	defer streamCarry.reset(key)

	split := len(token) / 2
	first := []byte("data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"" + token[:split] + "\"}}]}\n\n")
	if _, handled := restoreSemanticStream(key, first, restoreTokenPattern(), []string{label}, allowed, getSharedVault(), "text/event-stream", formatOpenAI); !handled {
		t.Fatal("initial OpenAI frame was not handled")
	}

	body := []byte("event: message\r\ndata: { \"object\": \"chat.completion.chunk\", \"choices\": [{\"index\": 0, \"delta\": {\"content\": \"\"}}]}\r\n\r\n")
	out, handled := restoreSemanticStream(key, body, restoreTokenPattern(), []string{label}, allowed, getSharedVault(), "text/event-stream", formatOpenAI)
	if !handled || !bytes.Equal(out, body) {
		t.Fatalf("empty delta with unchanged pending text was rewritten: handled=%v out=%q want=%q", handled, out, body)
	}
}

func TestSemanticPendingFailsOpenWhenEntryWouldExceedByteBudget(t *testing.T) {
	const (
		key      = "stream"
		label    = "REDACTED"
		fragment = "<REDACTED_1"
	)
	tokenRe := tokenPattern(label)

	t.Run("new entry includes stream key", func(t *testing.T) {
		channel := "openai-response:item:" + strings.Repeat("x", 32) + ":output:0:content:0"
		store := newStreamStoreWithLimits(time.Minute, len(key)+len(channel)+len(fragment)-1)
		owner := map[string]any{"delta": fragment}
		frame := &semanticFrame{}

		store.rewriteSemanticParts(key, map[string][]*semanticPart{
			channel: {{frame: frame, channel: channel, owner: owner, field: "delta", text: fragment, hasText: true}},
		}, tokenRe, []string{label}, nil, newVault(1, time.Hour))

		store.mu.Lock()
		defer store.mu.Unlock()
		entry := store.entries[key]
		if _, retained := entry.content[channel]; retained {
			t.Fatal("over-budget channel was retained on a new stream entry")
		}
		if entry.bytes > store.maxBytes || store.totalBytes > store.maxBytes {
			t.Fatalf("new stream state exceeds budget: entry=%d total=%d max=%d", entry.bytes, store.totalBytes, store.maxBytes)
		}
		if owner["delta"] != fragment || frame.changed {
			t.Fatalf("new stream fragment did not fail open unchanged: owner=%#v changed=%v", owner, frame.changed)
		}
	})

	t.Run("new channel preserves existing state", func(t *testing.T) {
		channel := "openai-response:item:" + strings.Repeat("x", 64) + ":output:0:content:0"
		baseBytes := len(key) + len("carry") + len("allowed") + len("existing") + len("pending")
		store := newStreamStoreWithLimits(time.Minute, baseBytes+len(channel)+len(fragment)-1)

		store.mu.Lock()
		entry := store.getOrCreateLocked(key, time.Now())
		entry.carry = []byte("carry")
		entry.allowed = map[string]struct{}{"allowed": {}}
		entry.hasAllow = true
		entry.content = map[string]string{"existing": "pending"}
		store.resizeEntryLocked(entry)
		store.mu.Unlock()

		owner := map[string]any{"delta": fragment}
		frame := &semanticFrame{}
		store.rewriteSemanticParts(key, map[string][]*semanticPart{
			channel: {{frame: frame, channel: channel, owner: owner, field: "delta", text: fragment, hasText: true}},
		}, tokenRe, []string{label}, nil, newVault(1, time.Hour))

		store.mu.Lock()
		defer store.mu.Unlock()
		entry = store.entries[key]
		if _, retained := entry.content[channel]; retained {
			t.Fatal("over-budget semantic channel was retained")
		}
		if entry.content["existing"] != "pending" {
			t.Fatalf("existing semantic state changed: %#v", entry.content)
		}
		if entry.bytes > store.maxBytes || store.totalBytes > store.maxBytes {
			t.Fatalf("stream state exceeds budget: entry=%d total=%d max=%d", entry.bytes, store.totalBytes, store.maxBytes)
		}
		if owner["delta"] != fragment || frame.changed {
			t.Fatalf("new pending fragment did not fail open unchanged: owner=%#v changed=%v", owner, frame.changed)
		}
	})

	t.Run("existing channel emits all pending and current bytes", func(t *testing.T) {
		channel := "openai-response:item:msg:output:0:content:0"
		pending := "<REDACTED_"
		store := newStreamStoreWithLimits(time.Minute, len(key)+len(channel)+len(pending))

		store.mu.Lock()
		entry := store.getOrCreateLocked(key, time.Now())
		entry.content = map[string]string{channel: pending}
		store.resizeEntryLocked(entry)
		store.mu.Unlock()

		owner := map[string]any{"delta": "1"}
		frame := &semanticFrame{}
		store.rewriteSemanticParts(key, map[string][]*semanticPart{
			channel: {{frame: frame, channel: channel, owner: owner, field: "delta", text: "1", hasText: true}},
		}, tokenRe, []string{label}, nil, newVault(1, time.Hour))

		store.mu.Lock()
		defer store.mu.Unlock()
		entry = store.entries[key]
		if _, retained := entry.content[channel]; retained {
			t.Fatal("over-budget existing semantic channel was retained")
		}
		if entry.bytes > store.maxBytes || store.totalBytes > store.maxBytes {
			t.Fatalf("stream state exceeds budget: entry=%d total=%d max=%d", entry.bytes, store.totalBytes, store.maxBytes)
		}
		if got, want := owner["delta"], pending+"1"; got != want || !frame.changed {
			t.Fatalf("pending and current bytes did not fail open: got=%#v want=%q changed=%v", got, want, frame.changed)
		}
	})
}

func TestSemanticStreamChannelLimitFailsOpen(t *testing.T) {
	const (
		key      = "semantic-channel-limit"
		label    = "REDACTED"
		fragment = "<REDACTED_1"
		extra    = 3
	)
	streamCarry.reset(key)
	defer streamCarry.reset(key)
	choices := make([]any, 0, streamAllowlistMaxTokens+extra)
	for i := 0; i < streamAllowlistMaxTokens+extra; i++ {
		choices = append(choices, map[string]any{
			"index": i,
			"delta": map[string]any{"content": fragment},
		})
	}
	payload, ok := encodeSemanticJSON(map[string]any{
		"object":  "chat.completion.chunk",
		"choices": choices,
	})
	if !ok {
		t.Fatal("encode channel-limit event")
	}
	body := append([]byte("data: "), payload...)
	body = append(body, '\n', '\n')
	out, handled := restoreSemanticStream(key, body, tokenPattern(label), []string{label}, nil, newVault(1, time.Hour), "text/event-stream", formatOpenAI)
	if !handled {
		t.Fatal("channel-limit OpenAI event was not handled")
	}
	frames := parseSemanticSSEFrames(out)
	if len(frames) != 1 {
		t.Fatalf("channel-limit output has %d frames, want 1", len(frames))
	}
	root := frames[0].doc.(map[string]any)
	deliveredChoices := root["choices"].([]any)

	streamCarry.mu.Lock()
	defer streamCarry.mu.Unlock()
	entry := streamCarry.entries[key]
	if got := len(entry.content); got != streamAllowlistMaxTokens {
		t.Fatalf("tracked semantic channels = %d, want cap %d", got, streamAllowlistMaxTokens)
	}
	for i, rawChoice := range deliveredChoices {
		channel := fmt.Sprintf("openai:choice:%d", i)
		_, retained := entry.content[channel]
		delta := rawChoice.(map[string]any)["delta"].(map[string]any)
		if i < streamAllowlistMaxTokens {
			if !retained || delta["content"] != "" {
				t.Fatalf("first-seen channel %q was not retained in order: retained=%v delta=%#v", channel, retained, delta["content"])
			}
		} else if retained || delta["content"] != fragment {
			t.Fatalf("overflow channel %q did not fail open: retained=%v delta=%#v", channel, retained, delta["content"])
		}
	}
}

func TestSemanticMalformedEventDoesNotCreatePending(t *testing.T) {
	setSharedVault(newVault(16, time.Hour))
	label := "REDACTED"
	secret := "malformed-event-secret"
	token := makeToken(label, secret)
	getSharedVault().Put(token, secret)
	allowed := collectTokens([]byte(token), restoreTokenPattern(), getSharedVault())
	key := "semantic-malformed-event"
	streamCarry.reset(key)
	defer streamCarry.reset(key)

	split := len(token) / 2
	body := []byte("event: response.output_text.delta\n" +
		"data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_privacy\",\"output_index\":0,\"content_index\":0,\"delta\":\"" + token[:split] + "\"\n\n" +
		"event: response.output_text.delta\n" +
		"data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_privacy\",\"output_index\":0,\"content_index\":0,\"delta\":\"" + token[split:] + "\"}\n\n")
	out, handled := restoreSemanticStream(key, body, restoreTokenPattern(), []string{label}, allowed, getSharedVault(), "text/event-stream", formatOpenAIResponse)
	if !handled {
		t.Fatal("valid event following malformed JSON was not handled")
	}
	if !bytes.Equal(out, body) {
		t.Fatalf("malformed event seeded semantic pending: out=%q want=%q", out, body)
	}

	streamCarry.mu.Lock()
	defer streamCarry.mu.Unlock()
	if entry := streamCarry.entries[key]; entry != nil && len(entry.content) != 0 {
		t.Fatalf("malformed event left semantic pending state: %#v", entry.content)
	}
}
