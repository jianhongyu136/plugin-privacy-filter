package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/sirupsen/logrus"
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

// okEnvelopeOut mirrors envelope but carries the result as a value so a success
// response is marshaled in a single pass, rather than marshaling the result to
// json.RawMessage and then marshaling the envelope around it.
type okEnvelopeOut struct {
	OK     bool `json:"ok"`
	Result any  `json:"result,omitempty"`
}

func okEnvelope(v any) ([]byte, error) {
	return json.Marshal(okEnvelopeOut{OK: true, Result: v})
}

func errorEnvelope(code, message string) []byte {
	out, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return out
}

func errorEnvelopeStatus(code, message string, httpStatus int) []byte {
	out, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message, HTTPStatus: httpStatus}})
	return out
}

type terminationErrorBody struct {
	Error terminationErrorDetail `json:"error"`
}

type terminationErrorDetail struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

func terminateRequest(reason string) pluginapi.RequestInterceptResponse {
	body, _ := json.Marshal(terminationErrorBody{Error: terminationErrorDetail{
		Message: reason,
		Type:    "permission_error",
		Code:    "privacy_filter_rejected",
	}})
	return pluginapi.RequestInterceptResponse{
		Terminate:       true,
		StatusCode:      http.StatusForbidden,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
		ResponseBody:    body,
	}
}

// pluginShutdown releases in-memory secrets when the host unloads the plugin.
func pluginShutdown() {
	streamCarry.stopCleanup()
	streamCarry.clear()
	if v := getSharedVault(); v != nil {
		v.stopCleanup()
		v.Clear()
	}
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		cfg, err := parseLifecycleConfig(request)
		if err != nil {
			var schemaErr *unsupportedSchemaVersionError
			if errors.As(err, &schemaErr) {
				return errorEnvelope("unsupported_schema_version", schemaErr.Error()), nil
			}
			return errorEnvelope("invalid_config", err.Error()), nil
		}
		if err := applyConfig(cfg); err != nil {
			return errorEnvelope("invalid_config", err.Error()), nil
		}
		return okEnvelope(pluginRegistration())

	case pluginabi.MethodRequestInterceptBefore, pluginabi.MethodRequestInterceptAfter:
		return handleRequestIntercept(request)

	case pluginabi.MethodResponseInterceptAfter:
		return handleResponseIntercept(request)

	case pluginabi.MethodResponseInterceptStreamChunk:
		return handleStreamChunkIntercept(request)

	case pluginabi.MethodPluginShutdown:
		pluginShutdown()
		return okEnvelope(struct{}{})

	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

// registrationCapability mirrors the host rpcCapabilities JSON names.
type registrationCapability struct {
	RequestInterceptor             bool `json:"request_interceptor"`
	ResponseInterceptor            bool `json:"response_interceptor"`
	StreamChunkInterceptor         bool `json:"response_stream_interceptor"`
	StreamChunkInterceptorStateful bool `json:"response_stream_interceptor_stateful"`
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginSchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "Privacy Filter",
			Version:          "0.0.3",
			Author:           "jhy",
			GitHubRepository: "https://github.com/jianhongyu136/plugin-privacy-filter",
			ConfigFields:     configFields(),
		},
		Capabilities: registrationCapability{
			RequestInterceptor:             true,
			ResponseInterceptor:            true,
			StreamChunkInterceptor:         true,
			StreamChunkInterceptorStateful: true,
		},
	}
}

func handleRequestIntercept(request []byte) (out []byte, err error) {
	// Fail closed: any panic while redacting the outbound request must reject
	// the request, never let un-redacted secrets reach the upstream. The host
	// turns a plugin error into fail-open (request forwarded unchanged), so we
	// convert internal failures into an explicit termination response instead.
	defer func() {
		if r := recover(); r != nil {
			out, err = okEnvelope(terminateRequest("privacy-filter panic while redacting request"))
		}
	}()

	var req pluginapi.RequestInterceptRequest
	if e := json.Unmarshal(request, &req); e != nil {
		return okEnvelope(terminateRequest("privacy-filter could not parse request: " + e.Error()))
	}
	st := activeSnapshot()
	if st == nil {
		// Not configured yet: reject rather than forward an unscanned request.
		return okEnvelope(terminateRequest("privacy-filter not configured"))
	}

	switch classifyFormat(req.SourceFormat) {
	case dispositionReject:
		// An unrecognized text format cannot be scanned safely (its content
		// regions are unknown), so fail closed rather than forward it unscanned.
		return okEnvelope(terminateRequest("privacy-filter does not support source format: " + req.SourceFormat))
	}

	redactVault := st.vault
	if st.mode == modeBlock {
		// Blocked requests never reach upstream, so their plaintext mappings are
		// unnecessary and must not evict mappings for legitimate in-flight calls.
		redactVault = nil
	}
	redact := newRedactFunc(st.label, redactVault)
	// Request interception may run both before and after other plugins. Use the
	// all-label candidate pattern plus an exact vault lookup so a token emitted
	// before a reconfigure remains idempotent without trusting forged candidates.
	requestTokens := existingTokenMatcher{candidate: st.restoreTokenRe, vault: st.vault}
	var result scanResult
	var handled bool
	var scanErr *contentScanError
	if st.mode == modeBlock {
		result, handled, scanErr = scanRequestContentForBlock(req.Body, req.SourceFormat, st.rules, requestTokens, redact, st.blockReturnOriginal)
	} else {
		result, handled, scanErr = scanRequestContent(req.Body, req.SourceFormat, st.rules, requestTokens, redact)
	}
	if scanErr != nil {
		fields := logrus.Fields{
			"stage":         "request",
			"source_format": req.SourceFormat,
			"path":          scanErr.Path,
			"error":         scanErr.Detail,
		}
		if scanErr.HasUnsupportedContent {
			fields["unsupported_content"] = sanitizeUnsupportedContent(scanErr.UnsupportedContent)
		}
		logrus.WithFields(fields).Warn("privacy-filter rejected unscannable request content")
		return okEnvelope(terminateRequest("privacy-filter could not scan request content at " + scanErr.Path + ": " + scanErr.Detail))
	}
	if !handled {
		// A recognized format whose body could not be parsed into its content
		// regions: reject rather than forward a body we could not scan.
		return okEnvelope(terminateRequest("privacy-filter could not parse " + req.SourceFormat + " request body"))
	}
	logScanMatches("request", result.Matches)
	if st.mode == modeBlock && len(result.Matches) > 0 {
		return okEnvelope(terminateRequest(blockRejectReason(result.Matches)))
	}

	var resp pluginapi.RequestInterceptResponse
	if len(result.Matches) > 0 {
		resp.Body = result.Body
	}
	return okEnvelope(resp)
}

const blockReasonMaxFindings = 8

func blockRejectReason(matches []scanMatch) string {
	var out strings.Builder
	out.WriteString("privacy-filter blocked request: ")
	limit := len(matches)
	if limit > blockReasonMaxFindings {
		limit = blockReasonMaxFindings
	}
	for i := 0; i < limit; i++ {
		if i > 0 {
			out.WriteString("; ")
		}
		match := matches[i]
		out.WriteString(match.Rule)
		out.WriteString(" (")
		out.WriteString(match.RuleType)
		out.WriteString(") at ")
		out.WriteString(match.Path)
		out.WriteString(": ")
		var quoted bytes.Buffer
		encoder := json.NewEncoder(&quoted)
		encoder.SetEscapeHTML(false)
		_ = encoder.Encode(match.Context)
		out.Write(bytes.TrimSuffix(quoted.Bytes(), []byte{'\n'}))
	}
	if remaining := len(matches) - limit; remaining > 0 {
		out.WriteString("; ... and ")
		out.WriteString(strconv.Itoa(remaining))
		out.WriteString(" more")
	}
	return out.String()
}

func handleResponseIntercept(request []byte) ([]byte, error) {
	var req pluginapi.ResponseInterceptRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return errorEnvelope("invalid_request", err.Error()), nil
	}
	st := activeSnapshot()
	if st == nil {
		return okEnvelope(pluginapi.ResponseInterceptResponse{})
	}
	tokenRe := st.restoreTokenRe
	// Restrict restoration to tokens this request actually emitted (present in
	// the redacted request body sent upstream), so a response can never surface
	// a secret minted for a different request that shares the process vault.
	allowed := collectTokens(req.RequestBody, tokenRe, st.vault)
	contentType := req.ResponseHeaders.Get("Content-Type")
	mediaType := strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0])
	restored := restoreBodyForMediaType(req.Body, tokenRe, allowed, st.vault, mediaType, req.SourceFormat)
	var resp pluginapi.ResponseInterceptResponse
	if len(restored) > 0 && !bytes.Equal(restored, req.Body) {
		resp.Body = restored
	}
	return okEnvelope(resp)
}

func handleStreamChunkIntercept(request []byte) ([]byte, error) {
	var req pluginapi.StreamChunkInterceptRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return errorEnvelope("invalid_request", err.Error()), nil
	}
	st := activeSnapshot()
	if req.ChunkIndex == pluginapi.StreamChunkEndIndex {
		if req.StreamID != "" {
			streamCarry.end(req.StreamID)
		}
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	if req.ChunkIndex == pluginapi.StreamChunkHeaderInitIndex {
		if req.StreamID != "" {
			// Stateful path: the host provides a stable StreamID and sends the
			// heavy RequestBody only on this header-init call. Cache the
			// request-scoped allowlist now so payload chunks need not carry the
			// request body, letting the host stop re-sending it and the plugin
			// stop hashing/scanning it on every chunk.
			streamCarry.begin(req.StreamID)
			if st != nil {
				tokenRe := st.restoreTokenRe
				streamCarry.allowlist(req.StreamID, func() map[string]struct{} {
					return collectTokens(req.RequestBody, tokenRe, st.vault)
				})
			}
			return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
		}
		resetStreamCarry(req.RequestBody)
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	if st == nil {
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	tokenRe := st.restoreTokenRe
	var key string
	var allowed map[string]struct{}
	if req.StreamID != "" {
		// Stateful path: reuse the allowlist cached at the header-init call,
		// keyed by StreamID, without touching RequestBody. If the entry was
		// removed under a hard memory cap, build from RequestBody when the host
		// still sends it; otherwise there is nothing to restore.
		key = req.StreamID
		allowed = streamCarry.allowlist(key, func() map[string]struct{} {
			return collectTokens(req.RequestBody, tokenRe, st.vault)
		})
		if len(allowed) == 0 {
			return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
		}
	} else {
		// Legacy path: no StreamID, so derive the per-stream key by hashing the
		// request body the host re-sends on every chunk.
		if tokenRe.Find(req.RequestBody) == nil && !bytes.Contains(req.RequestBody, []byte(`\u00`)) {
			return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
		}
		key = streamKey(req.RequestBody)
		// Build the request-scoped allowlist once per stream and reuse it for
		// every chunk, rather than re-scanning the full request body each chunk.
		allowed = streamCarry.allowlist(key, func() map[string]struct{} {
			return collectTokens(req.RequestBody, tokenRe, st.vault)
		})
	}
	contentType := req.ResponseHeaders.Get("Content-Type")
	mediaType := strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0])
	out, drop := detokenizeStreamChunkForMediaType(
		key,
		req.Body,
		tokenRe,
		tokenLabels(allowed),
		allowed,
		st.vault,
		mediaType,
		req.SourceFormat,
	)
	var resp pluginapi.StreamChunkInterceptResponse
	if drop {
		// The whole chunk was withheld pending a token split across the next
		// boundary. Drop it so the host does not deliver the still-tokenized
		// original; the withheld bytes are emitted with a later chunk.
		resp.DropChunk = true
	} else if !bytes.Equal(out, req.Body) {
		if len(out) == 0 {
			resp.DropChunk = true
		} else {
			resp.Body = out
		}
	}
	return okEnvelope(resp)
}

const scanLogMaxPaths = 8

const unsupportedContentLogMaxRunes = 160

func sanitizeUnsupportedContent(value string) string {
	runes := make([]rune, 0, unsupportedContentLogMaxRunes)
	for _, r := range value {
		if len(runes) == unsupportedContentLogMaxRunes {
			return string(runes[:unsupportedContentLogMaxRunes-3]) + "..."
		}
		if unicode.IsControl(r) {
			r = ' '
		}
		runes = append(runes, r)
	}
	return string(runes)
}

// logScanMatches logs only bounded metadata grouped by rule name and type. It
// never logs the original value, token, or scan context.
func logScanMatches(stage string, matches []scanMatch) {
	if len(matches) == 0 {
		return
	}
	type groupKey struct {
		rule     string
		ruleType string
	}
	type group struct {
		key          groupKey
		hits         int
		paths        []string
		seenPaths    map[string]struct{}
		omittedPaths int
	}

	byKey := make(map[groupKey]*group)
	ordered := make([]*group, 0)
	for _, match := range matches {
		key := groupKey{rule: match.Rule, ruleType: match.RuleType}
		current := byKey[key]
		if current == nil {
			current = &group{key: key, seenPaths: make(map[string]struct{})}
			byKey[key] = current
			ordered = append(ordered, current)
		}
		current.hits++
		if _, seen := current.seenPaths[match.Path]; seen {
			continue
		}
		current.seenPaths[match.Path] = struct{}{}
		if len(current.paths) < scanLogMaxPaths {
			current.paths = append(current.paths, match.Path)
		} else {
			current.omittedPaths++
		}
	}

	for _, current := range ordered {
		fields := logrus.Fields{
			"stage": stage,
			"rule":  current.key.rule,
			"type":  current.key.ruleType,
			"hits":  current.hits,
			"paths": current.paths,
		}
		if current.omittedPaths > 0 {
			fields["omitted_paths"] = current.omittedPaths
		}
		logrus.WithFields(fields).Info("privacy-filter redacted values")
	}
}
