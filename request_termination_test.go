package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type requestInterceptResult struct {
	pluginapi.RequestInterceptResponse
	Reject       bool
	RejectReason string
}

func requestResult(t *testing.T, response pluginapi.RequestInterceptResponse) requestInterceptResult {
	t.Helper()
	result := requestInterceptResult{
		RequestInterceptResponse: response,
		Reject:                   response.Terminate,
	}
	if !response.Terminate {
		return result
	}

	var payload terminationErrorBody
	if err := json.Unmarshal(response.ResponseBody, &payload); err != nil {
		t.Fatalf("termination response body is not valid JSON: %v", err)
	}
	result.RejectReason = payload.Error.Message
	return result
}

func TestTerminateRequestReturnsJSONForbidden(t *testing.T) {
	t.Parallel()

	reason := "privacy-filter rejected request: line\nbreak"
	response := terminateRequest(reason)

	if !response.Terminate {
		t.Fatal("termination response did not stop the request")
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	if got := response.ResponseHeaders.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q, want application/json", got)
	}
	if len(response.Body) != 0 {
		t.Fatalf("termination response unexpectedly rewrote request body: %s", response.Body)
	}

	var payload terminationErrorBody
	if err := json.Unmarshal(response.ResponseBody, &payload); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if payload.Error.Message != reason {
		t.Fatalf("error message = %q, want %q", payload.Error.Message, reason)
	}
	if payload.Error.Type != "permission_error" {
		t.Fatalf("error type = %q, want permission_error", payload.Error.Type)
	}
	if payload.Error.Code != "privacy_filter_rejected" {
		t.Fatalf("error code = %q, want privacy_filter_rejected", payload.Error.Code)
	}
}
