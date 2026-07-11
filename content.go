package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

// Source-format identifiers as reported by the host in
// RequestInterceptRequest.SourceFormat (the inbound handler type, verbatim).
const (
	formatOpenAI         = "openai"
	formatOpenAIResponse = "openai-response"
	formatClaude         = "claude"
	formatGemini         = "gemini"
	formatOpenAIImage    = "openai-image"
	formatOpenAIVideo    = "openai-video"
)

// formatDisposition decides how the request interceptor treats a source format.
type formatDisposition int

const (
	// dispositionRedact: a recognized text format whose content regions are
	// scanned and redacted.
	dispositionRedact formatDisposition = iota
	// dispositionReject: any other (text) format is rejected fail-closed rather
	// than forwarded unscanned.
	dispositionReject
)

// classifyFormat maps a source format to its request-interceptor disposition.
func classifyFormat(sourceFormat string) formatDisposition {
	switch sourceFormat {
	case formatOpenAI, formatOpenAIResponse, formatClaude, formatGemini, formatOpenAIImage, formatOpenAIVideo:
		return dispositionRedact
	default:
		return dispositionReject
	}
}

// scanRequestContent redacts only the content regions of a recognized request
// format (user/assistant/tool message text and system prompts), never the
// surrounding structure such as tool/function JSON schemas, model name, or
// sampling parameters. Walking the whole document would collapse a schema
// object whose key happens to match a field rule (for example a tool parameter
// named "api_key"), which corrupts the request. Restricting redaction to
// content regions keeps the request structurally intact.
//
// It returns handled=false when the body is not a single JSON object (so the
// content regions cannot be located) or the format is unrecognized; the caller
// treats that as a reason to reject the request.
func scanRequestContent(body []byte, sourceFormat string, rules ruleSet, tokenRe tokenMatcher, redact redactFunc) (scanResult, bool, *contentScanError) {
	return scanRequestContentWithMode(body, sourceFormat, rules, tokenRe, redact, false)
}

// scanRequestContentForBlock validates the complete request, then stops rule
// scanning after the first finding. Blocked bodies are never sent upstream, so
// the mutated document is deliberately not re-encoded.
func scanRequestContentForBlock(body []byte, sourceFormat string, rules ruleSet, tokenRe tokenMatcher, redact redactFunc) (scanResult, bool, *contentScanError) {
	return scanRequestContentWithMode(body, sourceFormat, rules, tokenRe, redact, true)
}

func scanRequestContentWithMode(body []byte, sourceFormat string, rules ruleSet, tokenRe tokenMatcher, redact redactFunc, stopAfterFirst bool) (scanResult, bool, *contentScanError) {
	doc, ok := decodeJSONObject(body)
	if !ok {
		return scanResult{}, false, nil
	}

	// Validate the complete structure before any real scanner can write a
	// token mapping. A rejected request must not retain plaintext or evict an
	// unrelated in-flight mapping from the bounded vault.
	// Validation deliberately has neither rules nor a token matcher, so even
	// checking an existing token cannot change vault LRU state for a request that
	// will later be rejected.
	validate := &scanner{}
	if handled, err := scanFormatContent(validate, doc, sourceFormat); !handled {
		return scanResult{}, false, nil
	} else if err != nil {
		return scanResult{}, true, err
	}

	s := &scanner{rules: rules, tokenRe: tokenRe, redact: redact, stopAfterFirst: stopAfterFirst}
	var scanErr *contentScanError
	if stopAfterFirst {
		scanErr = scanFormatContentUntilBlockMatch(s, doc, sourceFormat)
	} else {
		_, scanErr = scanFormatContent(s, doc, sourceFormat)
	}
	if scanErr != nil {
		return scanResult{}, true, scanErr
	}

	if len(s.matches) == 0 {
		// Nothing redacted: return the original bytes so token-free bodies are
		// not reformatted.
		return scanResult{Body: body, Matches: nil}, true, nil
	}
	if stopAfterFirst {
		return scanResult{Matches: s.matches}, true, nil
	}
	return scanResult{Body: reencodeJSON(doc, body), Matches: s.matches}, true, nil
}

func scanFormatContentUntilBlockMatch(s *scanner, doc map[string]any, sourceFormat string) (scanErr *contentScanError) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if _, stopped := recovered.(blockScanStopped); stopped {
				scanErr = nil
				return
			}
			panic(recovered)
		}
	}()
	_, scanErr = scanFormatContent(s, doc, sourceFormat)
	return scanErr
}

func decodeJSONObject(body []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return nil, false
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return doc, true
}

func scanFormatContent(s *scanner, doc map[string]any, sourceFormat string) (bool, *contentScanError) {
	switch sourceFormat {
	case formatOpenAI:
		return true, scanOpenAIContent(s, doc)
	case formatOpenAIResponse:
		return true, scanOpenAIResponseContent(s, doc)
	case formatClaude:
		return true, scanClaudeContent(s, doc)
	case formatGemini:
		return true, scanGeminiContent(s, doc)
	case formatOpenAIImage, formatOpenAIVideo:
		return true, scanImageVideoContent(s, doc)
	default:
		return false, nil
	}
}

// scanImageVideoContent scans only the textual generation prompt. Media and
// generation option fields remain outside the scanner.
func scanImageVideoContent(s *scanner, doc map[string]any) *contentScanError {
	rawPrompt, exists := doc["prompt"]
	if !exists {
		return nil
	}
	prompt, ok := rawPrompt.(string)
	if !ok {
		return &contentScanError{Path: "prompt", Detail: "prompt must be a string"}
	}
	doc["prompt"] = s.scanText(prompt, "prompt")
	return nil
}

// contentScanError describes content that cannot be scanned safely. Detail is
// deliberately sanitized so it can be returned and logged without including
// any part of the argument value.
type contentScanError struct {
	Path   string
	Detail string
}

// scanContentValue scans one content region. A plain string is scanned with the
// value rules; a nested structure (array of content blocks, object) is walked
// so field and value rules apply to the strings inside it. Because this is only
// ever called on content regions, field rules never reach request structure.
func (s *scanner) scanContentValue(node any, path string) any {
	if str, ok := node.(string); ok {
		return s.scanText(str, path)
	}
	return s.walk(node, path)
}

// scanOpenAIContent scans the content of every message (user, assistant, tool).
// OpenAI chat/completions bodies carry messages[].content as either a string or
// an array of content parts.
func scanOpenAIContent(s *scanner, doc map[string]any) *contentScanError {
	rawMessages, exists := doc["messages"]
	if !exists {
		return &contentScanError{Path: "messages", Detail: "messages is required"}
	}
	msgs, ok := rawMessages.([]any)
	if !ok {
		return &contentScanError{Path: "messages", Detail: "messages must be an array"}
	}
	for i, m := range msgs {
		messagePath := "messages[" + strconv.Itoa(i) + "]"
		msg, ok := m.(map[string]any)
		if !ok {
			return &contentScanError{Path: messagePath, Detail: "message must be an object"}
		}
		if err := validateAllowedKeys(msg, messagePath,
			"role", "content", "name", "refusal", "reasoning_content", "tool_calls",
			"function_call", "tool_call_id", "audio"); err != nil {
			return err
		}
		if c, ok := msg["content"]; ok {
			walked, err := scanOpenAIMessageContent(s, c, messagePath+".content", true)
			if err != nil {
				return err
			}
			msg["content"] = walked
		}
		if err := scanNullableStringMember(s, msg, "refusal", messagePath); err != nil {
			return err
		}
		if err := scanNullableStringMember(s, msg, "reasoning_content", messagePath); err != nil {
			return err
		}
		if err := scanOpenAIAudio(s, msg, messagePath); err != nil {
			return err
		}
		if err := scanOpenAIToolCallArguments(s, msg, messagePath); err != nil {
			return err
		}
		if err := scanOpenAILegacyFunctionCallArguments(s, msg, messagePath); err != nil {
			return err
		}
	}
	return nil
}

func scanOpenAIAudio(s *scanner, msg map[string]any, path string) *contentScanError {
	raw, exists := msg["audio"]
	if !exists || raw == nil {
		return nil
	}
	audio, ok := raw.(map[string]any)
	if !ok {
		return &contentScanError{Path: path + ".audio", Detail: "audio must be an object or null"}
	}
	if err := validateAllowedKeys(audio, path+".audio", "id", "data", "expires_at", "transcript"); err != nil {
		return err
	}
	return scanNullableStringMember(s, audio, "transcript", path+".audio")
}

func scanOpenAILegacyFunctionCallArguments(s *scanner, msg map[string]any, messagePath string) *contentScanError {
	rawFunctionCall, exists := msg["function_call"]
	if !exists || rawFunctionCall == nil {
		return nil
	}
	functionPath := messagePath + ".function_call"
	functionCall, ok := rawFunctionCall.(map[string]any)
	if !ok {
		return &contentScanError{Path: functionPath, Detail: "function_call must be an object"}
	}
	if err := validateAllowedKeys(functionCall, functionPath, "name", "arguments"); err != nil {
		return err
	}
	rawArguments, exists := functionCall["arguments"]
	if !exists {
		return nil
	}
	argumentsPath := functionPath + ".arguments"
	arguments, ok := rawArguments.(string)
	if !ok {
		return &contentScanError{Path: argumentsPath, Detail: "arguments must be a string"}
	}
	redacted, changed, err := scanFunctionArgumentsJSONString(s, arguments, argumentsPath)
	if err != nil {
		return err
	}
	if changed {
		functionCall["arguments"] = redacted
	}
	return nil
}

func scanOpenAIMessageContent(s *scanner, value any, path string, allowNull bool) (any, *contentScanError) {
	if value == nil {
		if allowNull {
			return nil, nil
		}
		return nil, &contentScanError{Path: path, Detail: "content must be a string or array"}
	}
	if text, ok := value.(string); ok {
		return s.scanText(text, path), nil
	}
	blocks, ok := value.([]any)
	if !ok {
		return nil, &contentScanError{Path: path, Detail: "content must be a string or array"}
	}
	for i, rawBlock := range blocks {
		blockPath := path + "[" + strconv.Itoa(i) + "]"
		block, ok := rawBlock.(map[string]any)
		if !ok {
			return nil, &contentScanError{Path: blockPath, Detail: "content block must be an object"}
		}
		kind, err := contentBlockType(block, blockPath)
		if err != nil {
			return nil, err
		}
		if err := validateOpenAIContentBlockKeys(block, blockPath, kind); err != nil {
			return nil, err
		}
		switch kind {
		case "text", "input_text", "image_url", "input_audio", "file":
			if err := validatePromptCacheBreakpoint(block, blockPath); err != nil {
				return nil, err
			}
		}
		switch kind {
		case "text", "input_text", "output_text":
			if err := scanStringMember(s, block, "text", blockPath, true); err != nil {
				return nil, err
			}
		case "refusal":
			if err := scanStringMember(s, block, "refusal", blockPath, true); err != nil {
				return nil, err
			}
		case "image_url", "input_audio", "file", "image_file":
			// Media and file payloads are deliberately outside the text scanner.
			if err := validateOpenAIMediaBlock(block, blockPath, kind); err != nil {
				return nil, err
			}
		default:
			return nil, unknownContentBlock(blockPath, kind)
		}
	}
	return blocks, nil
}

// scanOpenAIToolCallArguments scans runtime function arguments without walking
// tools[].function.parameters, which is a schema rather than user content.
func scanOpenAIToolCallArguments(s *scanner, msg map[string]any, messagePath string) *contentScanError {
	rawToolCalls, exists := msg["tool_calls"]
	if !exists || rawToolCalls == nil {
		return nil
	}
	toolCalls, ok := rawToolCalls.([]any)
	if !ok {
		return &contentScanError{Path: messagePath + ".tool_calls", Detail: "tool_calls must be an array"}
	}
	for i, rawToolCall := range toolCalls {
		toolCallPath := messagePath + ".tool_calls[" + strconv.Itoa(i) + "]"
		toolCall, ok := rawToolCall.(map[string]any)
		if !ok {
			return &contentScanError{Path: toolCallPath, Detail: "tool call must be an object"}
		}
		kind := "function"
		if rawType, exists := toolCall["type"]; exists {
			var ok bool
			kind, ok = rawType.(string)
			if !ok || kind == "" {
				return &contentScanError{Path: toolCallPath + ".type", Detail: "tool call type must be a non-empty string"}
			}
		}
		if kind == "custom" {
			if err := validateAllowedKeys(toolCall, toolCallPath, "id", "index", "type", "custom"); err != nil {
				return err
			}
			customPath := toolCallPath + ".custom"
			custom, ok := toolCall["custom"].(map[string]any)
			if !ok {
				return &contentScanError{Path: customPath, Detail: "custom is required and must be an object"}
			}
			if err := validateAllowedKeys(custom, customPath, "name", "input"); err != nil {
				return err
			}
			if err := scanStringMember(s, custom, "input", customPath, true); err != nil {
				return err
			}
			continue
		}
		if kind != "function" {
			return &contentScanError{Path: toolCallPath + ".type", Detail: "unsupported tool call type"}
		}
		if err := validateAllowedKeys(toolCall, toolCallPath, "id", "index", "type", "function"); err != nil {
			return err
		}
		rawFunction, exists := toolCall["function"]
		if !exists {
			return &contentScanError{Path: toolCallPath + ".function", Detail: "function is required"}
		}
		functionPath := toolCallPath + ".function"
		function, ok := rawFunction.(map[string]any)
		if !ok {
			return &contentScanError{Path: functionPath, Detail: "function must be an object"}
		}
		if err := validateAllowedKeys(function, functionPath, "name", "arguments"); err != nil {
			return err
		}
		rawArguments, exists := function["arguments"]
		if !exists {
			return &contentScanError{Path: functionPath + ".arguments", Detail: "arguments is required"}
		}
		argumentsPath := functionPath + ".arguments"
		arguments, ok := rawArguments.(string)
		if !ok {
			return &contentScanError{Path: argumentsPath, Detail: "arguments must be a string"}
		}
		if strings.TrimSpace(arguments) == "" {
			continue
		}

		redacted, changed, err := scanFunctionArgumentsJSONString(s, arguments, argumentsPath)
		if err != nil {
			return err
		}
		if changed {
			function["arguments"] = redacted
		}
	}
	return nil
}

func decodeToolCallArguments(arguments string) (any, string) {
	dec := json.NewDecoder(strings.NewReader(arguments))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, safeArgumentJSONError(err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, "arguments must contain exactly one JSON value"
		}
		return nil, safeArgumentJSONError(err)
	}
	return doc, ""
}

func safeArgumentJSONError(err error) string {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return "arguments contain incomplete JSON"
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return "arguments contain invalid JSON at byte " + strconv.FormatInt(syntaxErr.Offset, 10)
	}
	return "arguments contain invalid JSON"
}

func scanFunctionArgumentsJSONString(s *scanner, value, path string) (string, bool, *contentScanError) {
	if strings.TrimSpace(value) == "" {
		return value, false, nil
	}
	return scanStrictJSONString(s, value, path)
}

func scanStrictJSONString(s *scanner, value, path string) (string, bool, *contentScanError) {
	doc, detail := decodeToolCallArguments(value)
	if detail != "" {
		return "", false, &contentScanError{Path: path, Detail: detail}
	}
	matchCount := len(s.matches)
	doc = s.scanContentValue(doc, path)
	if len(s.matches) == matchCount {
		return value, false, nil
	}
	return string(reencodeJSON(doc, []byte(value))), true, nil
}

func validateAllowedKeys(object map[string]any, path string, keys ...string) *contentScanError {
	allowed := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		allowed[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return &contentScanError{Path: path, Detail: "unsupported object member"}
		}
	}
	return nil
}

func validateOptionalStringMember(object map[string]any, key, path string) *contentScanError {
	raw, exists := object[key]
	if !exists || raw == nil {
		return nil
	}
	if _, ok := raw.(string); !ok {
		return &contentScanError{Path: path + "." + key, Detail: key + " must be a string or null"}
	}
	return nil
}

func validatePromptCacheBreakpoint(object map[string]any, path string) *contentScanError {
	raw, exists := object["prompt_cache_breakpoint"]
	if !exists || raw == nil {
		return nil
	}
	breakpoint, ok := raw.(map[string]any)
	if !ok {
		return &contentScanError{Path: path + ".prompt_cache_breakpoint", Detail: "prompt_cache_breakpoint must be an object or null"}
	}
	breakpointPath := path + ".prompt_cache_breakpoint"
	if err := validateAllowedKeys(breakpoint, breakpointPath, "mode"); err != nil {
		return err
	}
	return validateOptionalStringMember(breakpoint, "mode", breakpointPath)
}

func validateResponsesCaller(item map[string]any, path string) *contentScanError {
	raw, exists := item["caller"]
	if !exists || raw == nil {
		return nil
	}
	caller, ok := raw.(map[string]any)
	if !ok {
		return &contentScanError{Path: path + ".caller", Detail: "caller must be an object or null"}
	}
	callerPath := path + ".caller"
	kind, err := contentBlockType(caller, callerPath)
	if err != nil {
		return err
	}
	switch kind {
	case "direct":
		return validateAllowedKeys(caller, callerPath, "type")
	case "program":
		if err := validateAllowedKeys(caller, callerPath, "type", "caller_id"); err != nil {
			return err
		}
		if _, exists := caller["caller_id"]; !exists {
			return &contentScanError{Path: callerPath + ".caller_id", Detail: "caller_id is required"}
		}
		return validateOptionalStringMember(caller, "caller_id", callerPath)
	default:
		return unknownContentBlock(callerPath, kind)
	}
}

func validateShellEnvironment(item map[string]any, path string) *contentScanError {
	raw, exists := item["environment"]
	if !exists || raw == nil {
		return nil
	}
	environment, ok := raw.(map[string]any)
	if !ok {
		return &contentScanError{Path: path + ".environment", Detail: "environment must be an object or null"}
	}
	environmentPath := path + ".environment"
	kind, err := contentBlockType(environment, environmentPath)
	if err != nil {
		return err
	}
	switch kind {
	case "local":
		return validateAllowedKeys(environment, environmentPath, "type")
	case "container_reference":
		if err := validateAllowedKeys(environment, environmentPath, "type", "container_id"); err != nil {
			return err
		}
		return validateOptionalStringMember(environment, "container_id", environmentPath)
	default:
		return unknownContentBlock(environmentPath, kind)
	}
}

func validateOpenAIContentBlockKeys(block map[string]any, path, kind string) *contentScanError {
	switch kind {
	case "text", "input_text":
		return validateAllowedKeys(block, path, "type", "text", "prompt_cache_breakpoint")
	case "output_text":
		return validateAllowedKeys(block, path, "type", "text")
	case "refusal":
		return validateAllowedKeys(block, path, "type", "refusal")
	case "image_url":
		return validateAllowedKeys(block, path, "type", "image_url", "prompt_cache_breakpoint")
	case "input_audio":
		return validateAllowedKeys(block, path, "type", "input_audio", "prompt_cache_breakpoint")
	case "file":
		return validateAllowedKeys(block, path, "type", "file", "prompt_cache_breakpoint")
	case "image_file":
		return validateAllowedKeys(block, path, "type", "image_file")
	default:
		return unknownContentBlock(path, kind)
	}
}

func validateOpenAIMediaBlock(block map[string]any, path, kind string) *contentScanError {
	var member string
	var keys []string
	switch kind {
	case "image_url":
		member, keys = "image_url", []string{"url", "detail"}
	case "input_audio":
		member, keys = "input_audio", []string{"data", "format"}
	case "file":
		member, keys = "file", []string{"file_data", "file_id", "filename"}
	case "image_file":
		member, keys = "image_file", []string{"file_id", "detail"}
	default:
		return nil
	}
	raw, exists := block[member]
	if !exists {
		return &contentScanError{Path: path + "." + member, Detail: member + " is required"}
	}
	value, ok := raw.(map[string]any)
	if !ok {
		return &contentScanError{Path: path + "." + member, Detail: member + " must be an object"}
	}
	return validateAllowedKeys(value, path+"."+member, keys...)
}

func contentBlockType(block map[string]any, path string) (string, *contentScanError) {
	rawType, exists := block["type"]
	if !exists {
		return "", &contentScanError{Path: path + ".type", Detail: "content block type is required"}
	}
	kind, ok := rawType.(string)
	if !ok || kind == "" {
		return "", &contentScanError{Path: path + ".type", Detail: "content block type must be a non-empty string"}
	}
	return kind, nil
}

func unknownContentBlock(path, _ string) *contentScanError {
	return &contentScanError{Path: path + ".type", Detail: "unsupported content block type"}
}

func scanStringMember(s *scanner, object map[string]any, key, path string, required bool) *contentScanError {
	raw, exists := object[key]
	if !exists {
		if required {
			return &contentScanError{Path: path + "." + key, Detail: key + " is required"}
		}
		return nil
	}
	value, ok := raw.(string)
	if !ok {
		return &contentScanError{Path: path + "." + key, Detail: key + " must be a string"}
	}
	object[key] = s.scanText(value, path+"."+key)
	return nil
}

// scanOpenAIResponseContent scans the OpenAI Responses input and instructions.
// input is a string or an array of input items; instructions is a string.
func scanOpenAIResponseContent(s *scanner, doc map[string]any) *contentScanError {
	inp, exists := doc["input"]
	if !exists {
		return &contentScanError{Path: "input", Detail: "input is required"}
	}
	walked, err := scanResponsesInput(s, inp, "input")
	if err != nil {
		return err
	}
	doc["input"] = walked
	if rawInstructions, exists := doc["instructions"]; exists && rawInstructions != nil {
		instr, ok := rawInstructions.(string)
		if !ok {
			return &contentScanError{Path: "instructions", Detail: "instructions must be a string"}
		}
		doc["instructions"] = s.scanText(instr, "instructions")
	}
	return nil
}

func scanResponsesInput(s *scanner, value any, path string) (any, *contentScanError) {
	if text, ok := value.(string); ok {
		return s.scanText(text, path), nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, &contentScanError{Path: path, Detail: "input must be a string or array"}
	}
	for i, rawItem := range items {
		itemPath := path + "[" + strconv.Itoa(i) + "]"
		if text, ok := rawItem.(string); ok {
			items[i] = s.scanText(text, itemPath)
			continue
		}
		item, ok := rawItem.(map[string]any)
		if !ok {
			return nil, &contentScanError{Path: itemPath, Detail: "input item must be a string or object"}
		}
		if _, hasType := item["type"]; !hasType {
			if id, hasID := item["id"].(string); hasID && id != "" {
				if _, hasRole := item["role"]; !hasRole {
					if _, hasContent := item["content"]; !hasContent {
						if len(item) == 1 {
							continue
						}
						return nil, &contentScanError{Path: itemPath, Detail: "item reference must contain only id"}
					}
				}
			}
			if _, hasRole := item["role"]; !hasRole {
				return nil, &contentScanError{Path: itemPath + ".type", Detail: "input item type or role is required"}
			}
			if _, ok := item["role"].(string); !ok {
				return nil, &contentScanError{Path: itemPath + ".role", Detail: "role must be a string"}
			}
			if err := validateAllowedKeys(item, itemPath, "role", "content", "phase"); err != nil {
				return nil, err
			}
			if err := validateOptionalStringMember(item, "phase", itemPath); err != nil {
				return nil, err
			}
			content, exists := item["content"]
			if !exists {
				return nil, &contentScanError{Path: itemPath + ".content", Detail: "content is required"}
			}
			walked, scanErr := scanResponsesContent(s, content, itemPath+".content")
			if scanErr != nil {
				return nil, scanErr
			}
			item["content"] = walked
			continue
		}
		kind, err := contentBlockType(item, itemPath)
		if err != nil {
			return nil, err
		}
		if err := validateResponsesItemKeys(item, itemPath, kind); err != nil {
			return nil, err
		}
		switch kind {
		case "function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output",
			"shell_call", "shell_call_output", "apply_patch_call", "apply_patch_call_output":
			if err := validateResponsesCaller(item, itemPath); err != nil {
				return nil, err
			}
		}
		switch kind {
		case "message":
			if err := validateOptionalStringMember(item, "phase", itemPath); err != nil {
				return nil, err
			}
			content, exists := item["content"]
			if !exists {
				return nil, &contentScanError{Path: itemPath + ".content", Detail: "content is required"}
			}
			walked, scanErr := scanResponsesContent(s, content, itemPath+".content")
			if scanErr != nil {
				return nil, scanErr
			}
			item["content"] = walked
		case "input_text", "output_text":
			if kind == "input_text" {
				if err := validatePromptCacheBreakpoint(item, itemPath); err != nil {
					return nil, err
				}
			}
			if err := scanStringMember(s, item, "text", itemPath, true); err != nil {
				return nil, err
			}
		case "refusal":
			if err := scanStringMember(s, item, "refusal", itemPath, true); err != nil {
				return nil, err
			}
		case "function_call":
			if err := validateOptionalStringMember(item, "namespace", itemPath); err != nil {
				return nil, err
			}
			rawArguments, exists := item["arguments"]
			if !exists {
				return nil, &contentScanError{Path: itemPath + ".arguments", Detail: "arguments is required"}
			}
			arguments, ok := rawArguments.(string)
			if !ok {
				return nil, &contentScanError{Path: itemPath + ".arguments", Detail: "arguments must be a string"}
			}
			redacted, changed, scanErr := scanFunctionArgumentsJSONString(s, arguments, itemPath+".arguments")
			if scanErr != nil {
				return nil, scanErr
			}
			if changed {
				item["arguments"] = redacted
			}
		case "function_call_output":
			rawOutput, exists := item["output"]
			if !exists {
				return nil, &contentScanError{Path: itemPath + ".output", Detail: "output is required"}
			}
			walked, scanErr := scanResponsesContent(s, rawOutput, itemPath+".output")
			if scanErr != nil {
				return nil, scanErr
			}
			item["output"] = walked
		case "custom_tool_call":
			if err := validateOptionalStringMember(item, "namespace", itemPath); err != nil {
				return nil, err
			}
			if err := scanStringMember(s, item, "input", itemPath, true); err != nil {
				return nil, err
			}
		case "custom_tool_call_output":
			rawOutput, exists := item["output"]
			if !exists {
				return nil, &contentScanError{Path: itemPath + ".output", Detail: "output is required"}
			}
			walked, scanErr := scanResponsesContent(s, rawOutput, itemPath+".output")
			if scanErr != nil {
				return nil, scanErr
			}
			item["output"] = walked
		case "reasoning":
			for _, member := range []string{"summary", "content"} {
				raw, exists := item[member]
				if !exists || raw == nil {
					continue
				}
				walked, scanErr := scanResponsesContent(s, raw, itemPath+"."+member)
				if scanErr != nil {
					return nil, scanErr
				}
				item[member] = walked
			}
		case "computer_call":
			if err := scanComputerCallActions(s, item, itemPath); err != nil {
				return nil, err
			}
			if err := scanComputerSafetyChecks(s, item, itemPath); err != nil {
				return nil, err
			}
		case "local_shell_call":
			if err := scanLocalShellCall(s, item, itemPath); err != nil {
				return nil, err
			}
		case "local_shell_call_output":
			if err := scanStrictJSONStringMember(s, item, "output", itemPath, true); err != nil {
				return nil, err
			}
		case "shell_call":
			if err := scanShellCall(s, item, itemPath); err != nil {
				return nil, err
			}
		case "shell_call_output":
			if err := scanShellCallOutput(s, item, itemPath); err != nil {
				return nil, err
			}
		case "apply_patch_call":
			if err := scanApplyPatchCall(s, item, itemPath); err != nil {
				return nil, err
			}
		case "apply_patch_call_output":
			if err := scanNullableStringMember(s, item, "output", itemPath); err != nil {
				return nil, err
			}
		case "mcp_list_tools":
			if err := scanNullableStringMember(s, item, "error", itemPath); err != nil {
				return nil, err
			}
		case "mcp_approval_request":
			if err := scanStrictJSONStringMember(s, item, "arguments", itemPath, true); err != nil {
				return nil, err
			}
		case "mcp_approval_response":
			if err := scanNullableStringMember(s, item, "reason", itemPath); err != nil {
				return nil, err
			}
		case "mcp_call":
			if err := scanStrictJSONStringMember(s, item, "arguments", itemPath, true); err != nil {
				return nil, err
			}
			if err := scanNullableStringMember(s, item, "error", itemPath); err != nil {
				return nil, err
			}
			if err := scanNullableStringMember(s, item, "output", itemPath); err != nil {
				return nil, err
			}
		case "program":
			if err := scanStringMember(s, item, "code", itemPath, true); err != nil {
				return nil, err
			}
		case "program_output":
			if err := scanStringMember(s, item, "result", itemPath, true); err != nil {
				return nil, err
			}
		case "code_interpreter_call":
			if err := scanCodeInterpreterCall(s, item, itemPath); err != nil {
				return nil, err
			}
		case "web_search_call":
			if err := scanWebSearchCall(s, item, itemPath); err != nil {
				return nil, err
			}
		case "file_search_call":
			if err := scanFileSearchCall(s, item, itemPath); err != nil {
				return nil, err
			}
		case "tool_search_call":
			rawArguments, exists := item["arguments"]
			if !exists {
				return nil, &contentScanError{Path: itemPath + ".arguments", Detail: "arguments is required"}
			}
			item["arguments"] = s.scanContentValue(rawArguments, itemPath+".arguments")
		case "tool_search_output", "additional_tools":
			// Tool definitions and their schemas are configuration, not runtime text.
		case "input_image", "input_file":
			if err := validatePromptCacheBreakpoint(item, itemPath); err != nil {
				return nil, err
			}
		case "computer_screenshot", "item_reference",
			"computer_call_output", "compaction", "compaction_trigger", "image_generation_call":
			// Media, file data, and identifiers remain byte-equivalent values.
		default:
			return nil, unknownContentBlock(itemPath, kind)
		}
	}
	return items, nil
}

func validateResponsesItemKeys(item map[string]any, path, kind string) *contentScanError {
	var keys []string
	switch kind {
	case "message":
		keys = []string{"type", "id", "role", "status", "content", "phase"}
	case "input_text":
		keys = []string{"type", "text", "annotations", "logprobs", "prompt_cache_breakpoint"}
	case "output_text":
		keys = []string{"type", "text", "annotations", "logprobs"}
	case "refusal":
		keys = []string{"type", "refusal"}
	case "function_call":
		keys = []string{"type", "id", "call_id", "name", "arguments", "status", "caller", "namespace"}
	case "function_call_output":
		keys = []string{"type", "id", "call_id", "output", "status", "caller"}
	case "custom_tool_call":
		keys = []string{"type", "id", "call_id", "name", "input", "status", "caller", "namespace"}
	case "custom_tool_call_output":
		keys = []string{"type", "id", "call_id", "output", "status", "caller"}
	case "reasoning":
		keys = []string{"type", "id", "summary", "content", "encrypted_content", "status"}
	case "computer_call":
		keys = []string{"type", "id", "call_id", "action", "actions", "pending_safety_checks", "status"}
	case "local_shell_call":
		keys = []string{"type", "id", "call_id", "action", "status"}
	case "local_shell_call_output":
		keys = []string{"type", "id", "output", "status"}
	case "shell_call":
		keys = []string{"type", "id", "call_id", "action", "status", "caller", "environment"}
	case "shell_call_output":
		keys = []string{"type", "id", "call_id", "output", "status", "caller"}
	case "apply_patch_call":
		keys = []string{"type", "id", "call_id", "operation", "status", "caller"}
	case "apply_patch_call_output":
		keys = []string{"type", "id", "call_id", "output", "status", "caller"}
	case "mcp_list_tools":
		keys = []string{"type", "id", "server_label", "tools", "error"}
	case "mcp_approval_request":
		keys = []string{"type", "id", "server_label", "name", "arguments"}
	case "mcp_approval_response":
		keys = []string{"type", "id", "approval_request_id", "approve", "reason"}
	case "mcp_call":
		keys = []string{"type", "id", "server_label", "name", "arguments", "approval_request_id", "error", "output", "status"}
	case "program":
		keys = []string{"type", "id", "code", "fingerprint"}
	case "program_output":
		keys = []string{"type", "id", "result"}
	case "code_interpreter_call":
		keys = []string{"type", "id", "container_id", "code", "outputs", "status"}
	case "web_search_call":
		keys = []string{"type", "id", "action", "status"}
	case "file_search_call":
		keys = []string{"type", "id", "queries", "results", "status"}
	case "tool_search_call":
		keys = []string{"type", "id", "arguments", "status"}
	case "tool_search_output", "additional_tools":
		keys = []string{"type", "id", "tools", "status"}
	case "input_image":
		keys = []string{"type", "detail", "file_id", "image_url", "prompt_cache_breakpoint"}
	case "input_file":
		keys = []string{"type", "file_data", "file_id", "file_url", "filename", "prompt_cache_breakpoint"}
	case "computer_screenshot":
		keys = []string{"type", "file_id", "image_url"}
	case "item_reference":
		keys = []string{"type", "id"}
	case "computer_call_output":
		keys = []string{"type", "id", "call_id", "output", "acknowledged_safety_checks", "status"}
	case "compaction":
		keys = []string{"type", "id", "encrypted_content"}
	case "compaction_trigger":
		keys = []string{"type"}
	case "image_generation_call":
		keys = []string{"type", "id", "result", "status"}
	default:
		return unknownContentBlock(path, kind)
	}
	return validateAllowedKeys(item, path, keys...)
}

func scanComputerSafetyChecks(s *scanner, item map[string]any, path string) *contentScanError {
	raw, exists := item["pending_safety_checks"]
	if !exists || raw == nil {
		return nil
	}
	checks, ok := raw.([]any)
	if !ok {
		return &contentScanError{Path: path + ".pending_safety_checks", Detail: "pending_safety_checks must be an array"}
	}
	for i, rawCheck := range checks {
		checkPath := path + ".pending_safety_checks[" + strconv.Itoa(i) + "]"
		check, ok := rawCheck.(map[string]any)
		if !ok {
			return &contentScanError{Path: checkPath, Detail: "safety check must be an object"}
		}
		if err := validateAllowedKeys(check, checkPath, "id", "code", "message"); err != nil {
			return err
		}
		if err := scanNullableStringMember(s, check, "message", checkPath); err != nil {
			return err
		}
	}
	return nil
}

func scanComputerCallActions(s *scanner, item map[string]any, path string) *contentScanError {
	rawAction, hasAction := item["action"]
	rawActions, hasActions := item["actions"]
	if hasAction == hasActions {
		return &contentScanError{Path: path + ".action", Detail: "exactly one of action or actions is required"}
	}
	if hasAction {
		action, ok := rawAction.(map[string]any)
		if !ok {
			return &contentScanError{Path: path + ".action", Detail: "action must be an object"}
		}
		return scanComputerAction(s, action, path+".action")
	}
	actions, ok := rawActions.([]any)
	if !ok {
		return &contentScanError{Path: path + ".actions", Detail: "actions must be an array"}
	}
	for i, raw := range actions {
		actionPath := path + ".actions[" + strconv.Itoa(i) + "]"
		action, ok := raw.(map[string]any)
		if !ok {
			return &contentScanError{Path: actionPath, Detail: "action must be an object"}
		}
		if err := scanComputerAction(s, action, actionPath); err != nil {
			return err
		}
	}
	return nil
}

func scanComputerAction(s *scanner, action map[string]any, path string) *contentScanError {
	kind, err := contentBlockType(action, path)
	if err != nil {
		return err
	}
	switch kind {
	case "type":
		if err := validateAllowedKeys(action, path, "type", "text"); err != nil {
			return err
		}
		return scanStringMember(s, action, "text", path, true)
	case "click", "double_click":
		return validateAllowedKeys(action, path, "type", "button", "x", "y")
	case "drag":
		return validateAllowedKeys(action, path, "type", "path")
	case "keypress":
		return validateAllowedKeys(action, path, "type", "keys")
	case "move":
		return validateAllowedKeys(action, path, "type", "x", "y")
	case "scroll":
		return validateAllowedKeys(action, path, "type", "scroll_x", "scroll_y", "x", "y")
	case "screenshot", "wait":
		return validateAllowedKeys(action, path, "type")
	default:
		return unknownContentBlock(path, kind)
	}
}

func scanLocalShellCall(s *scanner, item map[string]any, path string) *contentScanError {
	rawAction, exists := item["action"]
	if !exists {
		return &contentScanError{Path: path + ".action", Detail: "action is required"}
	}
	action, ok := rawAction.(map[string]any)
	if !ok {
		return &contentScanError{Path: path + ".action", Detail: "action must be an object"}
	}
	kind, err := contentBlockType(action, path+".action")
	if err != nil {
		return err
	}
	if kind != "exec" {
		return unknownContentBlock(path+".action", kind)
	}
	if err := validateAllowedKeys(action, path+".action", "type", "command", "env", "timeout_ms", "user", "working_directory"); err != nil {
		return err
	}
	if err := scanStringOrStringArrayMember(s, action, "command", path+".action", true); err != nil {
		return err
	}
	if rawEnv, exists := action["env"]; exists && rawEnv != nil {
		env, ok := rawEnv.(map[string]any)
		if !ok {
			return &contentScanError{Path: path + ".action.env", Detail: "env must be an object"}
		}
		for key, rawValue := range env {
			value, ok := rawValue.(string)
			if !ok {
				return &contentScanError{Path: path + ".action.env.*", Detail: "env value must be a string"}
			}
			env[key] = s.scanText(value, path+".action.env.*")
		}
	}
	if err := scanNullableStringMember(s, action, "user", path+".action"); err != nil {
		return err
	}
	if err := scanNullableStringMember(s, action, "working_directory", path+".action"); err != nil {
		return err
	}
	return nil
}

func scanStringOrStringArrayMember(s *scanner, object map[string]any, key, path string, required bool) *contentScanError {
	raw, exists := object[key]
	if !exists {
		if required {
			return &contentScanError{Path: path + "." + key, Detail: key + " is required"}
		}
		return nil
	}
	if value, ok := raw.(string); ok {
		object[key] = s.scanText(value, path+"."+key)
		return nil
	}
	values, ok := raw.([]any)
	if !ok {
		return &contentScanError{Path: path + "." + key, Detail: key + " must be a string or array"}
	}
	for i, rawValue := range values {
		value, ok := rawValue.(string)
		if !ok {
			return &contentScanError{Path: path + "." + key + "[" + strconv.Itoa(i) + "]", Detail: key + " item must be a string"}
		}
		values[i] = s.scanText(value, path+"."+key+"["+strconv.Itoa(i)+"]")
	}
	return nil
}

func scanStrictJSONStringMember(s *scanner, object map[string]any, key, path string, required bool) *contentScanError {
	raw, exists := object[key]
	if !exists {
		if required {
			return &contentScanError{Path: path + "." + key, Detail: key + " is required"}
		}
		return nil
	}
	value, ok := raw.(string)
	if !ok {
		return &contentScanError{Path: path + "." + key, Detail: key + " must be a string"}
	}
	redacted, changed, err := scanStrictJSONString(s, value, path+"."+key)
	if err != nil {
		return err
	}
	if changed {
		object[key] = redacted
	}
	return nil
}

func scanRequiredStringArrayMember(s *scanner, object map[string]any, key, path string) *contentScanError {
	raw, exists := object[key]
	if !exists {
		return &contentScanError{Path: path + "." + key, Detail: key + " is required"}
	}
	values, ok := raw.([]any)
	if !ok {
		return &contentScanError{Path: path + "." + key, Detail: key + " must be an array"}
	}
	for i, rawValue := range values {
		value, ok := rawValue.(string)
		if !ok {
			return &contentScanError{Path: path + "." + key + "[" + strconv.Itoa(i) + "]", Detail: key + " item must be a string"}
		}
		values[i] = s.scanText(value, path+"."+key+"["+strconv.Itoa(i)+"]")
	}
	return nil
}

func scanShellCall(s *scanner, item map[string]any, path string) *contentScanError {
	action, ok := item["action"].(map[string]any)
	if !ok {
		return &contentScanError{Path: path + ".action", Detail: "action is required and must be an object"}
	}
	if err := validateAllowedKeys(action, path+".action", "commands", "timeout_ms", "max_output_chars"); err != nil {
		return err
	}
	if err := validateShellEnvironment(item, path); err != nil {
		return err
	}
	return scanRequiredStringArrayMember(s, action, "commands", path+".action")
}

func scanShellCallOutput(s *scanner, item map[string]any, path string) *contentScanError {
	rawOutput, exists := item["output"]
	if !exists {
		return &contentScanError{Path: path + ".output", Detail: "output is required"}
	}
	output, ok := rawOutput.([]any)
	if !ok {
		return &contentScanError{Path: path + ".output", Detail: "output must be an array"}
	}
	for i, rawEntry := range output {
		entryPath := path + ".output[" + strconv.Itoa(i) + "]"
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			return &contentScanError{Path: entryPath, Detail: "output item must be an object"}
		}
		if err := validateAllowedKeys(entry, entryPath, "stdout", "stderr", "outcome"); err != nil {
			return err
		}
		if err := scanStringMember(s, entry, "stdout", entryPath, true); err != nil {
			return err
		}
		if err := scanStringMember(s, entry, "stderr", entryPath, true); err != nil {
			return err
		}
		outcome, ok := entry["outcome"].(map[string]any)
		if !ok {
			return &contentScanError{Path: entryPath + ".outcome", Detail: "outcome is required and must be an object"}
		}
		kind, err := contentBlockType(outcome, entryPath+".outcome")
		if err != nil {
			return err
		}
		if kind != "timeout" && kind != "exit" {
			return unknownContentBlock(entryPath+".outcome", kind)
		}
		if kind == "exit" {
			if err := validateAllowedKeys(outcome, entryPath+".outcome", "type", "exit_code"); err != nil {
				return err
			}
			if _, exists := outcome["exit_code"]; !exists {
				return &contentScanError{Path: entryPath + ".outcome.exit_code", Detail: "exit_code is required"}
			}
		} else if err := validateAllowedKeys(outcome, entryPath+".outcome", "type"); err != nil {
			return err
		}
	}
	return nil
}

func scanApplyPatchCall(s *scanner, item map[string]any, path string) *contentScanError {
	operation, ok := item["operation"].(map[string]any)
	if !ok {
		return &contentScanError{Path: path + ".operation", Detail: "operation is required and must be an object"}
	}
	kind, err := contentBlockType(operation, path+".operation")
	if err != nil {
		return err
	}
	switch kind {
	case "create_file", "update_file":
		if err := validateAllowedKeys(operation, path+".operation", "type", "path", "diff"); err != nil {
			return err
		}
		if err := scanStringMember(s, operation, "path", path+".operation", true); err != nil {
			return err
		}
		return scanStringMember(s, operation, "diff", path+".operation", true)
	case "delete_file":
		if err := validateAllowedKeys(operation, path+".operation", "type", "path"); err != nil {
			return err
		}
		return scanStringMember(s, operation, "path", path+".operation", true)
	default:
		return unknownContentBlock(path+".operation", kind)
	}
}

func scanCodeInterpreterCall(s *scanner, item map[string]any, path string) *contentScanError {
	if err := scanNullableStringMember(s, item, "code", path); err != nil {
		return err
	}
	rawOutputs, exists := item["outputs"]
	if !exists || rawOutputs == nil {
		return nil
	}
	outputs, ok := rawOutputs.([]any)
	if !ok {
		return &contentScanError{Path: path + ".outputs", Detail: "outputs must be an array or null"}
	}
	for i, rawOutput := range outputs {
		outputPath := path + ".outputs[" + strconv.Itoa(i) + "]"
		output, ok := rawOutput.(map[string]any)
		if !ok {
			return &contentScanError{Path: outputPath, Detail: "output must be an object"}
		}
		kind, err := contentBlockType(output, outputPath)
		if err != nil {
			return err
		}
		switch kind {
		case "logs":
			if err := validateAllowedKeys(output, outputPath, "type", "logs"); err != nil {
				return err
			}
			if err := scanStringMember(s, output, "logs", outputPath, true); err != nil {
				return err
			}
		case "image":
			if err := validateAllowedKeys(output, outputPath, "type", "url", "image_url"); err != nil {
				return err
			}
		default:
			return unknownContentBlock(outputPath, kind)
		}
	}
	return nil
}

func scanWebSearchCall(s *scanner, item map[string]any, path string) *contentScanError {
	action, ok := item["action"].(map[string]any)
	if !ok {
		return &contentScanError{Path: path + ".action", Detail: "action is required and must be an object"}
	}
	kind, err := contentBlockType(action, path+".action")
	if err != nil {
		return err
	}
	switch kind {
	case "search":
		if err := validateAllowedKeys(action, path+".action", "type", "query", "queries", "sources"); err != nil {
			return err
		}
		if err := scanOptionalStringArrayMember(s, action, "queries", path+".action"); err != nil {
			return err
		}
		if rawSources, exists := action["sources"]; exists && rawSources != nil {
			sources, ok := rawSources.([]any)
			if !ok {
				return &contentScanError{Path: path + ".action.sources", Detail: "sources must be an array or null"}
			}
			for i, rawSource := range sources {
				sourcePath := path + ".action.sources[" + strconv.Itoa(i) + "]"
				source, ok := rawSource.(map[string]any)
				if !ok {
					return &contentScanError{Path: sourcePath, Detail: "source must be an object"}
				}
				if err := validateAllowedKeys(source, sourcePath, "type", "url"); err != nil {
					return err
				}
			}
		}
		return scanNullableStringMember(s, action, "query", path+".action")
	case "find_in_page":
		if err := validateAllowedKeys(action, path+".action", "type", "pattern", "url"); err != nil {
			return err
		}
		return scanStringMember(s, action, "pattern", path+".action", true)
	case "open_page":
		return validateAllowedKeys(action, path+".action", "type", "url")
	default:
		return unknownContentBlock(path+".action", kind)
	}
}

func scanFileSearchCall(s *scanner, item map[string]any, path string) *contentScanError {
	if err := scanRequiredStringArrayMember(s, item, "queries", path); err != nil {
		return err
	}
	rawResults, exists := item["results"]
	if !exists || rawResults == nil {
		return nil
	}
	results, ok := rawResults.([]any)
	if !ok {
		return &contentScanError{Path: path + ".results", Detail: "results must be an array or null"}
	}
	for i, rawResult := range results {
		resultPath := path + ".results[" + strconv.Itoa(i) + "]"
		result, ok := rawResult.(map[string]any)
		if !ok {
			return &contentScanError{Path: resultPath, Detail: "result must be an object"}
		}
		if err := validateAllowedKeys(result, resultPath, "attributes", "file_id", "filename", "score", "text"); err != nil {
			return err
		}
		if rawAttributes, exists := result["attributes"]; exists && rawAttributes != nil {
			attributes, ok := rawAttributes.(map[string]any)
			if !ok {
				return &contentScanError{Path: resultPath + ".attributes", Detail: "attributes must be an object or null"}
			}
			result["attributes"] = s.scanContentValue(attributes, resultPath+".attributes")
		}
		if err := scanNullableStringMember(s, result, "text", resultPath); err != nil {
			return err
		}
	}
	return nil
}

func scanResponsesContent(s *scanner, value any, path string) (any, *contentScanError) {
	if text, ok := value.(string); ok {
		return s.scanText(text, path), nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, &contentScanError{Path: path, Detail: "content must be a string or array"}
	}
	for i, rawItem := range items {
		itemPath := path + "[" + strconv.Itoa(i) + "]"
		item, ok := rawItem.(map[string]any)
		if !ok {
			return nil, &contentScanError{Path: itemPath, Detail: "content block must be an object"}
		}
		kind, err := contentBlockType(item, itemPath)
		if err != nil {
			return nil, err
		}
		if err := validateResponsesContentKeys(item, itemPath, kind); err != nil {
			return nil, err
		}
		switch kind {
		case "input_text", "input_image", "input_file":
			if err := validatePromptCacheBreakpoint(item, itemPath); err != nil {
				return nil, err
			}
		}
		switch kind {
		case "input_text", "output_text", "text", "summary_text", "reasoning_text":
			if err := scanStringMember(s, item, "text", itemPath, true); err != nil {
				return nil, err
			}
		case "refusal":
			if err := scanStringMember(s, item, "refusal", itemPath, true); err != nil {
				return nil, err
			}
		case "input_image", "input_file", "computer_screenshot":
		default:
			return nil, unknownContentBlock(itemPath, kind)
		}
	}
	return items, nil
}

func validateResponsesContentKeys(item map[string]any, path, kind string) *contentScanError {
	switch kind {
	case "input_text":
		return validateAllowedKeys(item, path, "type", "text", "prompt_cache_breakpoint")
	case "output_text":
		return validateAllowedKeys(item, path, "type", "text", "annotations", "logprobs")
	case "text", "summary_text", "reasoning_text":
		return validateAllowedKeys(item, path, "type", "text")
	case "refusal":
		return validateAllowedKeys(item, path, "type", "refusal")
	case "input_image":
		return validateAllowedKeys(item, path, "type", "detail", "file_id", "image_url", "prompt_cache_breakpoint")
	case "input_file":
		return validateAllowedKeys(item, path, "type", "file_data", "file_id", "file_url", "filename", "prompt_cache_breakpoint")
	case "computer_screenshot":
		return validateAllowedKeys(item, path, "type", "file_id", "image_url")
	default:
		return unknownContentBlock(path, kind)
	}
}

// scanClaudeContent scans Anthropic messages[].content and the system prompt.
// content and system are each a string or an array of content blocks.
func scanClaudeContent(s *scanner, doc map[string]any) *contentScanError {
	rawMessages, exists := doc["messages"]
	if !exists {
		return &contentScanError{Path: "messages", Detail: "messages is required"}
	}
	msgs, ok := rawMessages.([]any)
	if !ok {
		return &contentScanError{Path: "messages", Detail: "messages must be an array"}
	}
	for i, m := range msgs {
		messagePath := "messages[" + strconv.Itoa(i) + "]"
		msg, ok := m.(map[string]any)
		if !ok {
			return &contentScanError{Path: messagePath, Detail: "message must be an object"}
		}
		if err := validateAllowedKeys(msg, messagePath, "role", "content"); err != nil {
			return err
		}
		c, exists := msg["content"]
		if !exists {
			return &contentScanError{Path: messagePath + ".content", Detail: "content is required"}
		}
		walked, err := scanClaudeBlocks(s, c, messagePath+".content", false)
		if err != nil {
			return err
		}
		msg["content"] = walked
	}
	if sys, exists := doc["system"]; exists {
		walked, err := scanClaudeBlocks(s, sys, "system", false)
		if err != nil {
			return err
		}
		doc["system"] = walked
	}
	return nil
}

func scanClaudeBlocks(s *scanner, value any, path string, allowNull bool) (any, *contentScanError) {
	if value == nil {
		if allowNull {
			return nil, nil
		}
		return nil, &contentScanError{Path: path, Detail: "content must be a string or array"}
	}
	if text, ok := value.(string); ok {
		return s.scanText(text, path), nil
	}
	blocks, ok := value.([]any)
	if !ok {
		return nil, &contentScanError{Path: path, Detail: "content must be a string or array"}
	}
	for i, rawBlock := range blocks {
		blockPath := path + "[" + strconv.Itoa(i) + "]"
		block, ok := rawBlock.(map[string]any)
		if !ok {
			return nil, &contentScanError{Path: blockPath, Detail: "content block must be an object"}
		}
		kind, err := contentBlockType(block, blockPath)
		if err != nil {
			return nil, err
		}
		if err := validateClaudeBlockKeys(block, blockPath, kind); err != nil {
			return nil, err
		}
		switch kind {
		case "text":
			if err := scanStringMember(s, block, "text", blockPath, true); err != nil {
				return nil, err
			}
		case "thinking":
			if err := scanStringMember(s, block, "thinking", blockPath, true); err != nil {
				return nil, err
			}
		case "tool_use", "server_tool_use":
			input, exists := block["input"]
			if !exists {
				return nil, &contentScanError{Path: blockPath + ".input", Detail: "input is required"}
			}
			if _, ok := input.(map[string]any); !ok {
				return nil, &contentScanError{Path: blockPath + ".input", Detail: "input must be an object"}
			}
			block["input"] = s.scanContentValue(input, blockPath+".input")
		case "tool_result", "mcp_tool_result", "web_search_tool_result", "web_fetch_tool_result",
			"code_execution_tool_result", "bash_code_execution_tool_result", "text_editor_code_execution_tool_result":
			content, exists := block["content"]
			if !exists {
				continue
			}
			walked, scanErr := scanClaudeToolResultContent(s, content, blockPath+".content")
			if scanErr != nil {
				return nil, scanErr
			}
			block["content"] = walked
		case "search_result":
			if err := scanStringMember(s, block, "title", blockPath, false); err != nil {
				return nil, err
			}
			content, exists := block["content"]
			if !exists {
				continue
			}
			walked, scanErr := scanClaudeBlocks(s, content, blockPath+".content", true)
			if scanErr != nil {
				return nil, scanErr
			}
			block["content"] = walked
		case "web_search_result", "web_fetch_result":
			if err := scanStringMember(s, block, "title", blockPath, false); err != nil {
				return nil, err
			}
			if err := scanStringMember(s, block, "text", blockPath, false); err != nil {
				return nil, err
			}
		case "document":
			if err := scanClaudeDocument(s, block, blockPath); err != nil {
				return nil, err
			}
		case "tool_search_tool_result":
			content, exists := block["content"]
			if !exists {
				return nil, &contentScanError{Path: blockPath + ".content", Detail: "content is required"}
			}
			walked, scanErr := scanClaudeToolSearchResult(s, content, blockPath+".content")
			if scanErr != nil {
				return nil, scanErr
			}
			block["content"] = walked
		case "mid_conv_system":
			content, exists := block["content"]
			if !exists {
				return nil, &contentScanError{Path: blockPath + ".content", Detail: "content is required"}
			}
			walked, scanErr := scanClaudeTextBlocks(s, content, blockPath+".content")
			if scanErr != nil {
				return nil, scanErr
			}
			block["content"] = walked
		case "tool_reference", "container_upload":
			// Tool names and references are protocol identifiers, not user text.
		case "image", "redacted_thinking":
			// Source data, URLs, MIME metadata, and encrypted thinking stay opaque.
		default:
			return nil, unknownContentBlock(blockPath, kind)
		}
	}
	return blocks, nil
}

func validateClaudeBlockKeys(block map[string]any, path, kind string) *contentScanError {
	switch kind {
	case "text":
		return validateAllowedKeys(block, path, "type", "text", "citations", "cache_control")
	case "thinking":
		return validateAllowedKeys(block, path, "type", "thinking", "signature", "cache_control")
	case "tool_use", "server_tool_use":
		return validateAllowedKeys(block, path, "type", "id", "name", "input", "caller", "cache_control")
	case "tool_result", "mcp_tool_result", "web_search_tool_result", "web_fetch_tool_result",
		"code_execution_tool_result", "bash_code_execution_tool_result", "text_editor_code_execution_tool_result":
		return validateAllowedKeys(block, path, "type", "tool_use_id", "content", "is_error", "cache_control")
	case "search_result":
		return validateAllowedKeys(block, path, "type", "source", "title", "content", "citations", "cache_control")
	case "web_search_result":
		return validateAllowedKeys(block, path, "type", "url", "title", "text", "page_age", "encrypted_content")
	case "web_fetch_result":
		return validateAllowedKeys(block, path, "type", "url", "title", "text", "content", "retrieved_at")
	case "document":
		return validateAllowedKeys(block, path, "type", "source", "title", "context", "citations", "cache_control")
	case "tool_search_tool_result":
		return validateAllowedKeys(block, path, "type", "tool_use_id", "content", "cache_control")
	case "mid_conv_system":
		return validateAllowedKeys(block, path, "type", "content")
	case "tool_reference":
		return validateAllowedKeys(block, path, "type", "tool_name")
	case "container_upload":
		return validateAllowedKeys(block, path, "type", "file_id")
	case "image":
		return validateAllowedKeys(block, path, "type", "source", "cache_control")
	case "redacted_thinking":
		return validateAllowedKeys(block, path, "type", "data")
	default:
		return unknownContentBlock(path, kind)
	}
}

func scanClaudeToolResultContent(s *scanner, value any, path string) (any, *contentScanError) {
	if value == nil {
		return nil, nil
	}
	if text, ok := value.(string); ok {
		return s.scanText(text, path), nil
	}
	if _, ok := value.([]any); ok {
		return scanClaudeBlocks(s, value, path, true)
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, &contentScanError{Path: path, Detail: "tool result content must be a string, array, object, or null"}
	}
	kind, err := contentBlockType(result, path)
	if err != nil {
		return nil, err
	}
	switch kind {
	case "web_fetch_result":
		if err := scanClaudeWebFetchResult(s, result, path); err != nil {
			return nil, err
		}
	case "code_execution_result", "bash_code_execution_result":
		if err := scanStringMember(s, result, "stdout", path, true); err != nil {
			return nil, err
		}
		if err := scanStringMember(s, result, "stderr", path, true); err != nil {
			return nil, err
		}
	case "encrypted_code_execution_result":
		if err := scanStringMember(s, result, "stderr", path, true); err != nil {
			return nil, err
		}
	case "text_editor_code_execution_view_result":
		fileType, ok := result["file_type"].(string)
		if !ok {
			return nil, &contentScanError{Path: path + ".file_type", Detail: "file_type must be a string"}
		}
		if _, ok := result["content"].(string); !ok {
			return nil, &contentScanError{Path: path + ".content", Detail: "content must be a string"}
		}
		switch fileType {
		case "text":
			if err := scanStringMember(s, result, "content", path, true); err != nil {
				return nil, err
			}
		case "image", "pdf":
			// Binary/media content remains opaque.
		default:
			return nil, &contentScanError{Path: path + ".file_type", Detail: "unsupported file_type"}
		}
	case "text_editor_code_execution_str_replace_result":
		if err := scanOptionalStringArrayMember(s, result, "lines", path); err != nil {
			return nil, err
		}
	case "text_editor_code_execution_tool_result_error":
		if err := scanNullableStringMember(s, result, "error_message", path); err != nil {
			return nil, err
		}
	case "text_editor_code_execution_create_result", "web_search_tool_result_error",
		"web_fetch_tool_result_error", "code_execution_tool_result_error",
		"bash_code_execution_tool_result_error":
		// Status flags and error codes are protocol metadata.
	default:
		return nil, unknownContentBlock(path, kind)
	}
	return result, nil
}

func scanClaudeWebFetchResult(s *scanner, result map[string]any, path string) *contentScanError {
	rawDocument, exists := result["content"]
	if !exists {
		return &contentScanError{Path: path + ".content", Detail: "content is required"}
	}
	document, ok := rawDocument.(map[string]any)
	if !ok {
		return &contentScanError{Path: path + ".content", Detail: "content must be an object"}
	}
	kind, err := contentBlockType(document, path+".content")
	if err != nil {
		return err
	}
	if kind != "document" {
		return unknownContentBlock(path+".content", kind)
	}
	return scanClaudeDocument(s, document, path+".content")
}

func scanClaudeDocument(s *scanner, document map[string]any, path string) *contentScanError {
	if err := scanNullableStringMember(s, document, "title", path); err != nil {
		return err
	}
	if err := scanNullableStringMember(s, document, "context", path); err != nil {
		return err
	}
	rawSource, exists := document["source"]
	if !exists {
		return &contentScanError{Path: path + ".source", Detail: "source is required"}
	}
	source, ok := rawSource.(map[string]any)
	if !ok {
		return &contentScanError{Path: path + ".source", Detail: "source must be an object"}
	}
	sourceType, err := contentBlockType(source, path+".source")
	if err != nil {
		return err
	}
	switch sourceType {
	case "text":
		return scanStringMember(s, source, "data", path+".source", true)
	case "content":
		rawContent, exists := source["content"]
		if !exists {
			return &contentScanError{Path: path + ".source.content", Detail: "content is required"}
		}
		walked, scanErr := scanClaudeDocumentSourceBlocks(s, rawContent, path+".source.content")
		if scanErr != nil {
			return scanErr
		}
		source["content"] = walked
	case "base64", "url":
		// PDF data and URLs stay opaque.
	default:
		return unknownContentBlock(path+".source", sourceType)
	}
	return nil
}

func scanClaudeDocumentSourceBlocks(s *scanner, value any, path string) (any, *contentScanError) {
	if text, ok := value.(string); ok {
		return s.scanText(text, path), nil
	}
	blocks, ok := value.([]any)
	if !ok {
		return nil, &contentScanError{Path: path, Detail: "content must be a string or array"}
	}
	for i, rawBlock := range blocks {
		blockPath := path + "[" + strconv.Itoa(i) + "]"
		block, ok := rawBlock.(map[string]any)
		if !ok {
			return nil, &contentScanError{Path: blockPath, Detail: "content block must be an object"}
		}
		kind, err := contentBlockType(block, blockPath)
		if err != nil {
			return nil, err
		}
		switch kind {
		case "text":
			if err := scanStringMember(s, block, "text", blockPath, true); err != nil {
				return nil, err
			}
		case "image":
			// Image payloads remain opaque.
		default:
			return nil, unknownContentBlock(blockPath, kind)
		}
	}
	return blocks, nil
}

func scanClaudeTextBlocks(s *scanner, value any, path string) (any, *contentScanError) {
	blocks, ok := value.([]any)
	if !ok {
		return nil, &contentScanError{Path: path, Detail: "content must be an array"}
	}
	for i, rawBlock := range blocks {
		blockPath := path + "[" + strconv.Itoa(i) + "]"
		block, ok := rawBlock.(map[string]any)
		if !ok {
			return nil, &contentScanError{Path: blockPath, Detail: "content block must be an object"}
		}
		kind, err := contentBlockType(block, blockPath)
		if err != nil {
			return nil, err
		}
		if kind != "text" {
			return nil, unknownContentBlock(blockPath, kind)
		}
		if err := scanStringMember(s, block, "text", blockPath, true); err != nil {
			return nil, err
		}
	}
	return blocks, nil
}

func scanClaudeToolSearchResult(s *scanner, value any, path string) (any, *contentScanError) {
	result, ok := value.(map[string]any)
	if !ok {
		return nil, &contentScanError{Path: path, Detail: "tool search result must be an object"}
	}
	kind, err := contentBlockType(result, path)
	if err != nil {
		return nil, err
	}
	switch kind {
	case "tool_search_tool_result_error":
		if err := scanNullableStringMember(s, result, "error_message", path); err != nil {
			return nil, err
		}
	case "tool_search_tool_search_result":
		rawReferences, exists := result["tool_references"]
		if !exists {
			return nil, &contentScanError{Path: path + ".tool_references", Detail: "tool_references is required"}
		}
		references, ok := rawReferences.([]any)
		if !ok {
			return nil, &contentScanError{Path: path + ".tool_references", Detail: "tool_references must be an array"}
		}
		for i, rawReference := range references {
			referencePath := path + ".tool_references[" + strconv.Itoa(i) + "]"
			reference, ok := rawReference.(map[string]any)
			if !ok {
				return nil, &contentScanError{Path: referencePath, Detail: "tool reference must be an object"}
			}
			referenceType, typeErr := contentBlockType(reference, referencePath)
			if typeErr != nil {
				return nil, typeErr
			}
			if referenceType != "tool_reference" {
				return nil, unknownContentBlock(referencePath, referenceType)
			}
		}
	default:
		return nil, unknownContentBlock(path, kind)
	}
	return result, nil
}

func scanOptionalStringArrayMember(s *scanner, object map[string]any, key, path string) *contentScanError {
	raw, exists := object[key]
	if !exists || raw == nil {
		return nil
	}
	values, ok := raw.([]any)
	if !ok {
		return &contentScanError{Path: path + "." + key, Detail: key + " must be an array or null"}
	}
	for i, rawValue := range values {
		value, ok := rawValue.(string)
		if !ok {
			return &contentScanError{Path: path + "." + key + "[" + strconv.Itoa(i) + "]", Detail: key + " item must be a string"}
		}
		values[i] = s.scanText(value, path+"."+key+"["+strconv.Itoa(i)+"]")
	}
	return nil
}

func scanNullableStringMember(s *scanner, object map[string]any, key, path string) *contentScanError {
	raw, exists := object[key]
	if !exists || raw == nil {
		return nil
	}
	value, ok := raw.(string)
	if !ok {
		return &contentScanError{Path: path + "." + key, Detail: key + " must be a string or null"}
	}
	object[key] = s.scanText(value, path+"."+key)
	return nil
}

// scanGeminiContent scans Gemini contents[].parts[].text and the system
// instruction parts. Both camelCase (systemInstruction) and snake_case
// (system_instruction) spellings are accepted by the Gemini API.
func scanGeminiContent(s *scanner, doc map[string]any) *contentScanError {
	rawContents, exists := doc["contents"]
	if !exists {
		return &contentScanError{Path: "contents", Detail: "contents is required"}
	}
	contents, ok := rawContents.([]any)
	if !ok {
		return &contentScanError{Path: "contents", Detail: "contents must be an array"}
	}
	for i, c := range contents {
		path := "contents[" + strconv.Itoa(i) + "]"
		content, ok := c.(map[string]any)
		if !ok {
			return &contentScanError{Path: path, Detail: "content must be an object"}
		}
		if err := validateAllowedKeys(content, path, "role", "parts"); err != nil {
			return err
		}
		if err := scanGeminiParts(s, content, path); err != nil {
			return err
		}
	}
	for _, key := range []string{"systemInstruction", "system_instruction"} {
		rawInstruction, exists := doc[key]
		if !exists {
			continue
		}
		si, ok := rawInstruction.(map[string]any)
		if !ok {
			return &contentScanError{Path: key, Detail: "system instruction must be an object"}
		}
		if err := validateAllowedKeys(si, key, "role", "parts"); err != nil {
			return err
		}
		if err := scanGeminiParts(s, si, key); err != nil {
			return err
		}
	}
	return nil
}

// scanGeminiParts scans text and runtime function data inside a Gemini Content
// object without walking media payloads or tool declarations.
func scanGeminiParts(s *scanner, content map[string]any, contentPath string) *contentScanError {
	partsPath := contentPath + ".parts"
	rawParts, exists := content["parts"]
	if !exists {
		return &contentScanError{Path: partsPath, Detail: "parts is required"}
	}
	parts, ok := rawParts.([]any)
	if !ok {
		return &contentScanError{Path: partsPath, Detail: "parts must be an array"}
	}
	for i, p := range parts {
		partPath := partsPath + "[" + strconv.Itoa(i) + "]"
		part, ok := p.(map[string]any)
		if !ok {
			return &contentScanError{Path: partPath, Detail: "part must be an object"}
		}
		allowedKeys := map[string]struct{}{
			"text": {}, "inlineData": {}, "fileData": {}, "functionCall": {},
			"functionResponse": {}, "executableCode": {}, "codeExecutionResult": {},
			"toolCall": {}, "toolResponse": {}, "thought": {}, "thoughtSignature": {},
			"videoMetadata": {}, "mediaResolution": {}, "partMetadata": {},
		}
		for key := range part {
			if _, allowed := allowedKeys[key]; !allowed {
				return &contentScanError{Path: partPath, Detail: "unsupported part field"}
			}
		}
		contentFields := 0
		if rawText, exists := part["text"]; exists {
			contentFields++
			t, ok := rawText.(string)
			if !ok {
				return &contentScanError{Path: partPath + ".text", Detail: "text must be a string"}
			}
			part["text"] = s.scanText(t, partPath+".text")
		}
		if rawCall, exists := part["functionCall"]; exists {
			contentFields++
			call, ok := rawCall.(map[string]any)
			if !ok {
				return &contentScanError{Path: partPath + ".functionCall", Detail: "functionCall must be an object"}
			}
			callPath := partPath + ".functionCall"
			if err := validateAllowedKeys(call, callPath, "id", "args", "name", "partialArgs", "willContinue"); err != nil {
				return err
			}
			if args, exists := call["args"]; exists {
				call["args"] = s.scanContentValue(args, callPath+".args")
			}
			if rawPartialArgs, exists := call["partialArgs"]; exists {
				partialArgs, ok := rawPartialArgs.([]any)
				if !ok {
					return &contentScanError{Path: callPath + ".partialArgs", Detail: "partialArgs must be an array"}
				}
				for j, rawPartial := range partialArgs {
					partialPath := callPath + ".partialArgs[" + strconv.Itoa(j) + "]"
					partial, ok := rawPartial.(map[string]any)
					if !ok {
						return &contentScanError{Path: partialPath, Detail: "partial argument must be an object"}
					}
					if err := validateAllowedKeys(partial, partialPath, "boolValue", "jsonPath", "nullValue", "numberValue", "stringValue", "willContinue"); err != nil {
						return err
					}
					if err := scanNullableStringMember(s, partial, "stringValue", partialPath); err != nil {
						return err
					}
				}
			}
		}
		if rawResponse, exists := part["functionResponse"]; exists {
			contentFields++
			response, ok := rawResponse.(map[string]any)
			if !ok {
				return &contentScanError{Path: partPath + ".functionResponse", Detail: "functionResponse must be an object"}
			}
			if err := validateAllowedKeys(response, partPath+".functionResponse", "id", "name", "response", "parts", "scheduling", "willContinue"); err != nil {
				return err
			}
			if value, exists := response["response"]; exists {
				response["response"] = s.scanContentValue(value, partPath+".functionResponse.response")
			}
		}
		if rawCall, exists := part["toolCall"]; exists {
			contentFields++
			call, ok := rawCall.(map[string]any)
			if !ok {
				return &contentScanError{Path: partPath + ".toolCall", Detail: "toolCall must be an object"}
			}
			if err := validateAllowedKeys(call, partPath+".toolCall", "id", "toolType", "args"); err != nil {
				return err
			}
			if args, exists := call["args"]; exists {
				call["args"] = s.scanContentValue(args, partPath+".toolCall.args")
			}
		}
		if rawResponse, exists := part["toolResponse"]; exists {
			contentFields++
			response, ok := rawResponse.(map[string]any)
			if !ok {
				return &contentScanError{Path: partPath + ".toolResponse", Detail: "toolResponse must be an object"}
			}
			if err := validateAllowedKeys(response, partPath+".toolResponse", "id", "toolType", "response"); err != nil {
				return err
			}
			if value, exists := response["response"]; exists {
				response["response"] = s.scanContentValue(value, partPath+".toolResponse.response")
			}
		}
		for _, key := range []string{"mediaResolution", "partMetadata"} {
			if raw, exists := part[key]; exists {
				if _, ok := raw.(map[string]any); !ok {
					return &contentScanError{Path: partPath + "." + key, Detail: key + " must be an object"}
				}
			}
		}
		for _, key := range []string{"inlineData", "fileData"} {
			if raw, exists := part[key]; exists {
				contentFields++
				if _, ok := raw.(map[string]any); !ok {
					return &contentScanError{Path: partPath + "." + key, Detail: key + " must be an object"}
				}
			}
		}
		if rawCode, exists := part["executableCode"]; exists {
			contentFields++
			code, ok := rawCode.(map[string]any)
			if !ok {
				return &contentScanError{Path: partPath + ".executableCode", Detail: "executableCode must be an object"}
			}
			if err := scanStringMember(s, code, "code", partPath+".executableCode", true); err != nil {
				return err
			}
		}
		if rawResult, exists := part["codeExecutionResult"]; exists {
			contentFields++
			result, ok := rawResult.(map[string]any)
			if !ok {
				return &contentScanError{Path: partPath + ".codeExecutionResult", Detail: "codeExecutionResult must be an object"}
			}
			if err := scanStringMember(s, result, "output", partPath+".codeExecutionResult", true); err != nil {
				return err
			}
		}
		if contentFields == 0 {
			return &contentScanError{Path: partPath, Detail: "part content is required"}
		}
	}
	return nil
}

func validateBlockContent(value any, path string, allowNull bool) *contentScanError {
	if value == nil {
		if allowNull {
			return nil
		}
		return &contentScanError{Path: path, Detail: "content must be a string or array"}
	}
	switch content := value.(type) {
	case string:
		return nil
	case []any:
		for i, item := range content {
			if _, ok := item.(map[string]any); !ok {
				return &contentScanError{Path: path + "[" + strconv.Itoa(i) + "]", Detail: "content block must be an object"}
			}
		}
		return nil
	default:
		return &contentScanError{Path: path, Detail: "content must be a string or array"}
	}
}

func validateInputContent(value any, path string) *contentScanError {
	switch input := value.(type) {
	case string:
		return nil
	case []any:
		for i, item := range input {
			switch item.(type) {
			case string, map[string]any:
			default:
				return &contentScanError{Path: path + "[" + strconv.Itoa(i) + "]", Detail: "input item must be a string or object"}
			}
		}
		return nil
	default:
		return &contentScanError{Path: path, Detail: "input must be a string or array"}
	}
}

// reencodeJSON serializes a decoded/modified JSON document with HTML escaping
// disabled (so token angle brackets survive) and the trailing newline trimmed.
// On failure it returns the original bytes rather than dropping content.
func reencodeJSON(doc any, original []byte) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return original
	}
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out
}
