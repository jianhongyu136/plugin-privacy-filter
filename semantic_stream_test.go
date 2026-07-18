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

func TestSemanticOpenAIChatBareJSONTerminalSkipsEmptyArgumentFlush(t *testing.T) {
	const (
		key   = "semantic-openai-bare-json-terminal"
		label = "REDACTED"
	)
	streamCarry.reset(key)
	defer streamCarry.reset(key)

	argument := []byte(`{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"value\":\"plain\"}"}}]},"finish_reason":null}]}`)
	if out, handled := restoreSemanticStream(key, argument, tokenPattern(label), []string{label}, nil, newVault(1, time.Hour), "text/event-stream", formatOpenAI); !handled || !bytes.Equal(out, argument) {
		t.Fatalf("bare JSON argument frame changed: handled=%v out=%q want=%q", handled, out, argument)
	}

	terminal := []byte(`{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`)
	out, handled := restoreSemanticStream(key, terminal, tokenPattern(label), []string{label}, nil, newVault(1, time.Hour), "text/event-stream", formatOpenAI)
	if !handled {
		t.Fatal("bare JSON terminal frame was not handled")
	}
	if !bytes.Equal(out, terminal) {
		t.Fatalf("bare JSON terminal emitted an empty argument flush: out=%q want=%q", out, terminal)
	}
	if !json.Valid(out) {
		t.Fatalf("bare JSON terminal became invalid JSON: %q", out)
	}
	streamCarry.mu.Lock()
	entry := streamCarry.entries[key]
	streamCarry.mu.Unlock()
	if entry != nil && len(entry.arguments) != 0 {
		t.Fatalf("bare JSON terminal retained argument state: %#v", entry.arguments)
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

func TestRewriteJSONArgumentOpsFlushesTailBeforeTerminal(t *testing.T) {
	const (
		key     = "argument-terminal"
		channel = "argument:openai:choice:0:tool:1"
		suffix  = `\u003cREDACTED_1a2b`
	)
	store := newStreamStore()
	owner := map[string]any{"arguments": `{"value":"` + suffix}
	partFrame := &semanticFrame{}
	terminalFrame := &semanticFrame{}
	ops := []semanticArgumentOp{
		{part: &semanticArgumentPart{
			frame: partFrame, channel: channel, owner: owner, field: "arguments",
			original: owner["arguments"], text: owner["arguments"].(string),
		}},
		{terminal: &semanticArgumentTerminal{
			frame: terminalFrame, channel: channel,
			flush: func(flushedChannel, tail string) bool {
				terminalFrame.before = append(terminalFrame.before, semanticSynthetic{doc: map[string]any{
					"channel": flushedChannel,
					"delta":   tail,
				}})
				return true
			},
		}},
	}

	store.rewriteJSONArgumentOps(key, ops, tokenPattern("REDACTED"), []string{"REDACTED"}, nil, newVault(1, time.Hour))

	if got, want := owner["arguments"], `{"value":"`; got != want || !partFrame.changed {
		t.Fatalf("split argument output = %#v, want %q; changed=%v", got, want, partFrame.changed)
	}
	if len(terminalFrame.before) != 1 {
		t.Fatalf("terminal synthetic deltas = %d, want 1", len(terminalFrame.before))
	}
	doc := terminalFrame.before[0].doc
	if got := doc["channel"]; got != channel {
		t.Fatalf("flushed channel = %#v, want %q", got, channel)
	}
	if got := doc["delta"]; got != suffix {
		t.Fatalf("flushed tail = %#v, want %q", got, suffix)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.entries[key].arguments[channel]; exists {
		t.Fatalf("terminal retained argument channel %q", channel)
	}
}

func TestRewriteJSONArgumentOpsRetainsLexicalStateWithoutTail(t *testing.T) {
	const (
		key     = "argument-lexical-state"
		channel = "argument:openai:choice:0:tool:1"
		label   = "REDACTED"
	)
	store := newStreamStore()
	firstOwner := map[string]any{"arguments": `{"value":"plain`}
	first := &semanticArgumentPart{
		frame: &semanticFrame{}, channel: channel, owner: firstOwner, field: "arguments",
		original: firstOwner["arguments"], text: firstOwner["arguments"].(string),
	}
	store.rewriteJSONArgumentOps(key, []semanticArgumentOp{{part: first}}, tokenPattern(label), []string{label}, nil, newVault(1, time.Hour))

	store.mu.Lock()
	state, exists := store.entries[key].arguments[channel]
	store.mu.Unlock()
	if !exists || state.tail != "" || state.next.mode != jsonArgumentInsideString {
		t.Fatalf("first fragment state = %+v, exists=%v; want empty tail inside string", state, exists)
	}

	token := makeToken(label, "secret")
	v := newVault(1, time.Hour)
	v.Put(token, "secret")
	secondOwner := map[string]any{"arguments": token + `"}`}
	second := &semanticArgumentPart{
		frame: &semanticFrame{}, channel: channel, owner: secondOwner, field: "arguments",
		original: secondOwner["arguments"], text: secondOwner["arguments"].(string),
	}
	store.rewriteJSONArgumentOps(key, []semanticArgumentOp{{part: second}}, tokenPattern(label), []string{label}, map[string]struct{}{token: {}}, v)

	if got, want := secondOwner["arguments"], `secret"}`; got != want || !second.frame.changed {
		t.Fatalf("second fragment output = %#v, want %q; changed=%v", got, want, second.frame.changed)
	}
}

func TestRewriteJSONArgumentOpsSharesVisibleChannelLimit(t *testing.T) {
	const (
		key     = "argument-shared-channel-limit"
		channel = "argument:openai:choice:0:tool:new"
		label   = "REDACTED"
	)
	store := newStreamStore()
	store.mu.Lock()
	entry := store.getOrCreateLocked(key, time.Now())
	entry.content = make(map[string]string, streamAllowlistMaxTokens)
	for i := 0; i < streamAllowlistMaxTokens; i++ {
		entry.content[fmt.Sprintf("visible:%d", i)] = "pending"
	}
	store.resizeEntryLocked(entry)
	store.mu.Unlock()

	token := makeToken(label, "secret")
	v := newVault(1, time.Hour)
	v.Put(token, "secret")
	fragment := `{"value":"` + token + `"}`
	owner := map[string]any{"arguments": fragment}
	part := &semanticArgumentPart{
		frame: &semanticFrame{}, channel: channel, owner: owner, field: "arguments",
		original: fragment, text: fragment,
	}
	store.rewriteJSONArgumentOps(key, []semanticArgumentOp{{part: part}}, tokenPattern(label), []string{label}, map[string]struct{}{token: {}}, v)

	store.mu.Lock()
	defer store.mu.Unlock()
	entry = store.entries[key]
	if got := owner["arguments"]; got != fragment || part.frame.changed {
		t.Fatalf("overflow argument changed: got=%#v want=%q changed=%v", got, fragment, part.frame.changed)
	}
	if !entry.argumentOverflow {
		t.Fatal("shared channel limit did not set argument overflow")
	}
	if _, exists := entry.arguments[channel]; exists {
		t.Fatalf("overflow argument channel %q was retained", channel)
	}
}

func TestRewriteJSONArgumentOpsFailsOpenAtByteLimit(t *testing.T) {
	const (
		key     = "stream"
		channel = "argument:openai:choice:0:tool:1"
		label   = "REDACTED"
		prior   = `\u003cREDACTED_`
		current = "1"
	)
	store := newStreamStoreWithLimits(time.Minute, len(key)+len(channel)+jsonArgumentStateFixedBytes+1)
	insideString := advanceJSONArgumentLex(jsonArgumentLexState{}, `{"value":"`)
	priorState := jsonArgumentState{
		tail:      prior,
		tailStart: insideString,
		next:      advanceJSONArgumentLex(insideString, prior),
	}
	store.mu.Lock()
	entry := store.getOrCreateLocked(key, time.Now())
	entry.arguments = map[string]jsonArgumentState{channel: priorState}
	store.resizeEntryLocked(entry)
	store.mu.Unlock()

	owner := map[string]any{"arguments": current}
	part := &semanticArgumentPart{
		frame: &semanticFrame{}, channel: channel, owner: owner, field: "arguments",
		original: current, text: current,
	}
	store.rewriteJSONArgumentOps(key, []semanticArgumentOp{{part: part}}, tokenPattern(label), []string{label}, nil, newVault(1, time.Hour))

	store.mu.Lock()
	defer store.mu.Unlock()
	entry = store.entries[key]
	if got, want := owner["arguments"], prior+current; got != want || !part.frame.changed {
		t.Fatalf("byte refusal output = %#v, want %q; changed=%v", got, want, part.frame.changed)
	}
	state := entry.arguments[channel]
	if !state.disabled || state.tail != "" {
		t.Fatalf("byte refusal state = %+v, want bounded disabled marker", state)
	}
	if entry.bytes > store.maxBytes || store.totalBytes > store.maxBytes {
		t.Fatalf("argument state exceeds budget: entry=%d total=%d max=%d", entry.bytes, store.totalBytes, store.maxBytes)
	}
}

func TestRewriteJSONArgumentOpsOverflowLatchStaysWithinExactByteLimit(t *testing.T) {
	const (
		key             = "exact-argument-limit"
		existingChannel = "argument:openai:choice:0:tool:0"
		refusedChannel  = "argument:openai:choice:0:tool:1"
		label           = "REDACTED"
	)
	store := newStreamStoreWithLimits(time.Minute, 1<<20)
	store.mu.Lock()
	entry := store.getOrCreateLocked(key, time.Now())
	entry.arguments = map[string]jsonArgumentState{
		existingChannel: {next: advanceJSONArgumentLex(jsonArgumentLexState{}, `{"sent":"plain"}`)},
	}
	store.resizeEntryLocked(entry)
	store.maxBytes = entry.bytes
	wantMax := store.maxBytes
	store.mu.Unlock()

	token := makeToken(label, "secret")
	fragment := `{"value":"` + token[:len(token)/2]
	owner := map[string]any{"arguments": fragment}
	part := &semanticArgumentPart{
		frame: &semanticFrame{}, channel: refusedChannel, owner: owner, field: "arguments",
		original: fragment, text: fragment,
	}
	store.rewriteJSONArgumentOps(key, []semanticArgumentOp{{part: part}}, tokenPattern(label), []string{label}, map[string]struct{}{token: {}}, newVault(1, time.Hour))

	store.mu.Lock()
	defer store.mu.Unlock()
	entry = store.entries[key]
	if got := owner["arguments"]; got != fragment || part.frame.changed {
		t.Fatalf("refused fragment did not fail open in source order: got=%#v want=%q changed=%v", got, fragment, part.frame.changed)
	}
	if !entry.argumentOverflow {
		t.Fatal("exact-limit refusal did not set argument overflow latch")
	}
	if _, exists := entry.arguments[existingChannel]; !exists {
		t.Fatalf("exact-limit refusal removed existing channel: %#v", entry.arguments)
	}
	if _, exists := entry.arguments[refusedChannel]; exists {
		t.Fatalf("exact-limit refusal retained new channel %q", refusedChannel)
	}
	if entry.bytes > wantMax || store.totalBytes > wantMax {
		t.Fatalf("overflow latch exceeded exact budget: entry=%d total=%d max=%d", entry.bytes, store.totalBytes, wantMax)
	}
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
