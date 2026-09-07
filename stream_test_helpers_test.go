package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// streamKey supplies deterministic request IDs to content-framing fixtures.
func streamKey(requestBody []byte) string {
	sum := sha256.Sum256(requestBody)
	return hex.EncodeToString(sum[:])
}

func resetStreamCarry(requestBody []byte) {
	streamCarry.reset(streamKey(requestBody))
}

func completeStream(t testing.TB, requestID string) json.RawMessage {
	t.Helper()
	request, err := json.Marshal(pluginapi.RequestCompletion{
		RequestID: requestID,
		Stream:    true,
		Outcome:   pluginapi.RequestCompletionSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handleMethod(pluginabi.MethodRequestComplete, request)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("request completion failed: envelope=%+v err=%v", env, err)
	}
	return env.Result
}
