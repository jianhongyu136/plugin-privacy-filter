package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestRequestCompletionPreventsLateStreamInitialization(t *testing.T) {
	for _, outcome := range []pluginapi.RequestCompletionOutcome{
		pluginapi.RequestCompletionSucceeded,
		pluginapi.RequestCompletionFailed,
		pluginapi.RequestCompletionRejected,
		pluginapi.RequestCompletionCanceled,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			callRegister(t, pluginabi.MethodPluginRegister, "")
			for _, initialized := range []bool{false, true} {
				requestID := t.Name()
				if initialized {
					requestID += "/initialized"
					initStreamWithID(t, formatOpenAI, requestID, []byte(`{"messages":[]}`))
				}
				completion := mustJSONMarshal(t, pluginapi.RequestCompletion{
					RequestID: requestID, Stream: true, Outcome: outcome,
				})
				raw, err := handleMethod(pluginabi.MethodRequestComplete, completion)
				if err != nil {
					t.Fatal(err)
				}
				var env envelope
				if err := json.Unmarshal(raw, &env); err != nil || !env.OK || string(env.Result) != "{}" {
					t.Fatalf("completion failed: envelope=%+v err=%v", env, err)
				}
				lateInit := mustJSONMarshal(t, pluginapi.StreamChunkInterceptRequest{
					RequestID: requestID, ChunkIndex: pluginapi.StreamChunkHeaderInitIndex,
					RequestBody: []byte(`{"messages":[]}`),
				})
				raw, err = handleMethod(pluginabi.MethodResponseInterceptStreamChunk, lateInit)
				if err != nil {
					t.Fatal(err)
				}
				env = envelope{}
				if err := json.Unmarshal(raw, &env); err != nil {
					t.Fatal(err)
				}
				if env.OK || env.Error == nil || !strings.Contains(env.Error.Message, "completed") {
					t.Fatalf("late init revived a completed request: %+v", env)
				}
			}
		})
	}
}

func TestRequestCompletionValidatesPayloadAndIgnoresNonStreams(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	for _, request := range []string{"not-json", `{}`, `{"RequestID":" \t ","Stream":true}`, `{"RequestID":123,"Stream":true}`} {
		raw, err := handleMethod(pluginabi.MethodRequestComplete, []byte(request))
		if err != nil {
			t.Fatal(err)
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil || env.OK || env.Error == nil || env.Error.Code != "invalid_request" {
			t.Fatalf("malformed completion was accepted: envelope=%+v err=%v", env, err)
		}
	}
	requestID := t.Name()
	raw, err := handleMethod(pluginabi.MethodRequestComplete, mustJSONMarshal(t, pluginapi.RequestCompletion{
		RequestID: requestID, Stream: false, Outcome: pluginapi.RequestCompletionSucceeded,
	}))
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("non-stream completion failed: envelope=%+v err=%v", env, err)
	}
	streamCarry.mu.Lock()
	_, retained := streamCarry.entries[requestID]
	streamCarry.mu.Unlock()
	if retained {
		t.Fatal("non-stream completion allocated stream state")
	}
}

func TestConcurrentStreamsWithIdenticalBodiesUseIndependentRequestIDs(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	st := activeSnapshot()
	const original = "concurrent-request-fixture"
	placeholder := makeToken(st.label, original)
	st.vault.Put(placeholder, original)
	requestBody := []byte(`{"messages":[{"content":"` + placeholder + `"}]}`)
	const streams = 16
	var firstBodies [streams][]byte
	var firstResponses [streams]pluginapi.StreamChunkInterceptResponse
	var group sync.WaitGroup
	for i := range streams {
		group.Go(func() {
			requestID := fmt.Sprintf("%s/%d", t.Name(), i)
			initStreamWithID(t, formatOpenAI, requestID, requestBody)
			split := len(placeholder)/2 + i%5
			firstBodies[i] = []byte(fmt.Sprintf("data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\n", placeholder[:split]))
			firstResponses[i] = invokeStreamBodyWithID(t, formatOpenAI, requestID, 0, firstBodies[i])
		})
	}
	group.Wait()
	if t.Failed() {
		return
	}
	for i := range streams {
		group.Go(func() {
			requestID := fmt.Sprintf("%s/%d", t.Name(), i)
			split := len(placeholder)/2 + i%5
			secondBody := []byte(fmt.Sprintf("data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\n", placeholder[split:]))
			second := invokeStreamBodyWithID(t, formatOpenAI, requestID, 1, secondBody)
			delivered := append(deliveredStreamBody(firstResponses[i], firstBodies[i]), deliveredStreamBody(second, secondBody)...)
			if got := openAIStreamContent(t, delivered); got != original {
				t.Errorf("request %s restored %q, want %q", requestID, got, original)
			}
			completeStream(t, requestID)
		})
	}
	group.Wait()
}

func TestRequestCompletionRacingWithInitializationDoesNotReviveState(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	requestID := t.Name()
	st := activeSnapshot()
	placeholder := makeToken(st.label, "lifecycle-fixture")
	st.vault.Put(placeholder, "lifecycle-fixture")
	request := mustJSONMarshal(t, pluginapi.StreamChunkInterceptRequest{
		RequestID: requestID, ChunkIndex: pluginapi.StreamChunkHeaderInitIndex,
		RequestBody: []byte(`{"input":"` + strings.Repeat(placeholder, 1<<16) + `"}`),
	})
	initialized := make(chan []byte, 1)
	go func() {
		raw, _ := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, request)
		initialized <- raw
	}()
	// Observe entry creation while allowlist construction is still allowed to
	// run. No timing sleep is needed to order completion after begin.
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for !streamCarry.has(requestID) {
		select {
		case <-deadline.C:
			t.Fatal("stream initialization did not start")
		default:
			runtime.Gosched()
		}
	}
	completeStream(t, requestID)
	raw := <-initialized
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("initialization failed: envelope=%+v err=%v", env, err)
	}
	streamCarry.mu.Lock()
	entry := streamCarry.entries[requestID]
	retained := entry != nil && (entry.active || entry.hasAllow || len(entry.allowed) != 0)
	streamCarry.mu.Unlock()
	if retained {
		t.Fatal("late initialization retained request payload state after completion")
	}
	lateChunk := mustJSONMarshal(t, pluginapi.StreamChunkInterceptRequest{
		RequestID: requestID, ChunkIndex: 0, Body: []byte(placeholder),
	})
	raw, err := handleMethod(pluginabi.MethodResponseInterceptStreamChunk, lateChunk)
	if err != nil {
		t.Fatal(err)
	}
	env = envelope{}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.OK || env.Error == nil || !strings.Contains(env.Error.Message, "not initialized") {
		t.Fatalf("late initialization revived stream state after completion: %+v", env)
	}
}
