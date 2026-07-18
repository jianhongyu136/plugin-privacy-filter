package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type semanticFraming uint8

const (
	semanticSSE semanticFraming = iota
	semanticJSON
)

type semanticSynthetic struct {
	event string
	doc   map[string]any
}

type semanticFrame struct {
	start        int
	next         int
	payloadStart int
	payloadEnd   int
	lineEnding   []byte
	dataLead     []byte
	event        string
	sentinel     string
	framing      semanticFraming
	doc          any
	opaque       bool
	changed      bool
	before       []semanticSynthetic
}

type semanticPart struct {
	frame    *semanticFrame
	channel  string
	owner    map[string]any
	field    string
	original any
	text     string
	hasText  bool
	terminal bool
	flush    func(string)
}

type semanticArgumentPart struct {
	frame    *semanticFrame
	channel  string
	owner    map[string]any
	field    string
	original any
	text     string
}

type semanticAtomicArgument struct {
	frame    *semanticFrame
	owner    map[string]any
	field    string
	original any
	text     string
}

type semanticArgumentTerminal struct {
	frame         *semanticFrame
	channel       string
	channelPrefix string
	flush         func(channel, tail string) bool
}

type semanticArgumentOp struct {
	part     *semanticArgumentPart
	terminal *semanticArgumentTerminal
}

type semanticTerminal struct {
	channelPrefix string
	flush         func(string) bool
}

type semanticBatch struct {
	frames          []*semanticFrame
	groups          map[string][]*semanticPart
	channelOrder    []string
	terminals       []*semanticTerminal
	excluded        []*semanticPart
	argumentOps     []semanticArgumentOp
	atomicArguments []*semanticAtomicArgument
}

func (b *semanticBatch) addPart(part *semanticPart) {
	if _, exists := b.groups[part.channel]; !exists {
		b.channelOrder = append(b.channelOrder, part.channel)
	}
	b.groups[part.channel] = append(b.groups[part.channel], part)
}

func (b *semanticBatch) addOpaqueFrame(frame *semanticFrame) {
	frame.opaque = true
	b.frames = append(b.frames, frame)
}

func nonnegativeJSONIndex(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	index, err := number.Int64()
	return index, err == nil && index >= 0
}

func decodeOneJSON(payload []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	var trailing any
	return doc, dec.Decode(&trailing) == io.EOF
}

// parseSemanticSSEFrames records complete, single-data-line JSON events. Other
// events remain outside the semantic frame list and use the generic SSE path.
func parseSemanticSSEFrames(data []byte) []*semanticFrame {
	var frames []*semanticFrame
	for start := 0; start < len(data); {
		cursor := start
		payloadStart, payloadEnd := -1, -1
		dataLines := 0
		var dataLead []byte
		event := ""
		var lineEnding []byte
		complete := false

		for cursor < len(data) {
			lineStart := cursor
			line, ending, next := nextSSELine(data, cursor)
			cursor = next
			if len(ending) == 0 {
				break
			}
			if len(line) == 0 {
				complete = true
				break
			}
			if bytes.HasPrefix(line, []byte("event:")) {
				value := line[len("event:"):]
				if len(value) > 0 && value[0] == ' ' {
					value = value[1:]
				}
				event = string(value)
			}
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			dataLines++
			if dataLines != 1 {
				continue
			}
			payloadStart = lineStart + len("data:")
			payloadEnd = lineStart + len(line)
			leadStart := payloadStart
			for payloadStart < payloadEnd && (data[payloadStart] == ' ' || data[payloadStart] == '\t') {
				payloadStart++
			}
			dataLead = append([]byte(nil), data[leadStart:payloadStart]...)
			lineEnding = append([]byte(nil), ending...)
		}

		if !complete {
			break
		}
		if dataLines == 1 {
			frame := &semanticFrame{
				start:        start,
				next:         cursor,
				payloadStart: payloadStart,
				payloadEnd:   payloadEnd,
				lineEnding:   lineEnding,
				dataLead:     dataLead,
				event:        event,
				framing:      semanticSSE,
			}
			payload := data[payloadStart:payloadEnd]
			if bytes.Equal(payload, []byte("[DONE]")) {
				frame.sentinel = "[DONE]"
				frame.opaque = true
				frames = append(frames, frame)
			} else if doc, ok := decodeOneJSON(payload); ok {
				frame.doc = doc
				frames = append(frames, frame)
			}
		}
		start = cursor
	}
	return frames
}

// parseAtomicSemanticSSEFrame accepts one complete JSON SSE event whose blank
// dispatch separator is added by the host after stream interception.
func parseAtomicSemanticSSEFrame(data []byte) (*semanticFrame, bool) {
	if len(data) == 0 || data[len(data)-1] == '\n' || data[len(data)-1] == '\r' || len(parseSemanticSSEFrames(data)) != 0 {
		return nil, false
	}

	framed := make([]byte, 0, len(data)+2)
	framed = append(framed, data...)
	framed = append(framed, '\n', '\n')

	frames := parseSemanticSSEFrames(framed)
	if len(frames) != 1 || frames[0].sentinel != "" || frames[0].start != 0 || frames[0].next != len(framed) || frames[0].payloadEnd > len(data) {
		return nil, false
	}
	frames[0].next = len(data)
	return frames[0], true
}

func openAIChatArgumentTerminal(frame *semanticFrame, channelPrefix string) *semanticArgumentTerminal {
	return &semanticArgumentTerminal{
		frame:         frame,
		channelPrefix: channelPrefix,
		flush: func(channel, tail string) bool {
			const choicePrefix = "argument:openai:choice:"
			rest, ok := strings.CutPrefix(channel, choicePrefix)
			if !ok {
				return false
			}
			choiceText, toolText, ok := strings.Cut(rest, ":tool:")
			if !ok || strings.Contains(toolText, ":") {
				return false
			}
			choiceIndex, err := strconv.ParseInt(choiceText, 10, 64)
			if err != nil || choiceIndex < 0 {
				return false
			}
			toolIndex, err := strconv.ParseInt(toolText, 10, 64)
			if err != nil || toolIndex < 0 {
				return false
			}
			frame.before = append(frame.before, semanticSynthetic{doc: map[string]any{
				"object": "chat.completion.chunk",
				"choices": []any{map[string]any{
					"index": choiceIndex,
					"delta": map[string]any{"tool_calls": []any{map[string]any{
						"index":    toolIndex,
						"function": map[string]any{"arguments": tail},
					}}},
					"finish_reason": nil,
				}},
			}})
			return true
		},
	}
}

// parseOpenAIChatSemantic adapts strict Chat Completions content deltas with
// explicit nonnegative choice indices to the common channel model.
func parseOpenAIChatSemantic(frames []*semanticFrame) semanticBatch {
	batch := semanticBatch{groups: make(map[string][]*semanticPart)}
	for _, frame := range frames {
		if frame.sentinel == "[DONE]" {
			batch.frames = append(batch.frames, frame)
			batch.argumentOps = append(batch.argumentOps, semanticArgumentOp{terminal: openAIChatArgumentTerminal(frame, "argument:openai:")})
			continue
		}
		root, ok := frame.doc.(map[string]any)
		if !ok {
			continue
		}
		if object, _ := root["object"].(string); object != "chat.completion.chunk" {
			continue
		}
		choices, ok := root["choices"].([]any)
		if !ok {
			batch.addOpaqueFrame(frame)
			continue
		}
		valid := true
		for _, rawChoice := range choices {
			choice, ok := rawChoice.(map[string]any)
			if !ok {
				valid = false
				break
			}
			if _, ok := nonnegativeJSONIndex(choice["index"]); !ok {
				valid = false
				break
			}
			delta, ok := choice["delta"].(map[string]any)
			if !ok {
				valid = false
				break
			}
			if content, exists := delta["content"]; exists && content != nil {
				if _, ok := content.(string); !ok {
					valid = false
					break
				}
			}
			if finishReason, exists := choice["finish_reason"]; exists && finishReason != nil {
				if _, ok := finishReason.(string); !ok {
					valid = false
					break
				}
			}
			rawToolCalls, exists := delta["tool_calls"]
			if !exists || rawToolCalls == nil {
				continue
			}
			toolCalls, ok := rawToolCalls.([]any)
			if !ok {
				valid = false
				break
			}
			for _, rawToolCall := range toolCalls {
				toolCall, ok := rawToolCall.(map[string]any)
				if !ok {
					valid = false
					break
				}
				rawFunction, exists := toolCall["function"]
				if !exists || rawFunction == nil {
					continue
				}
				function, ok := rawFunction.(map[string]any)
				if !ok {
					valid = false
					break
				}
				if arguments, exists := function["arguments"]; exists {
					if _, ok := arguments.(string); !ok {
						valid = false
						break
					}
				}
			}
			if !valid {
				break
			}
		}
		if !valid {
			batch.addOpaqueFrame(frame)
			continue
		}
		batch.frames = append(batch.frames, frame)
		for _, rawChoice := range choices {
			choice := rawChoice.(map[string]any)
			choiceIndex, _ := nonnegativeJSONIndex(choice["index"])
			delta := choice["delta"].(map[string]any)
			contentRaw := delta["content"]
			content, hasText := contentRaw.(string)
			part := &semanticPart{
				frame:    frame,
				channel:  "openai:choice:" + strconv.FormatInt(choiceIndex, 10),
				owner:    delta,
				field:    "content",
				original: contentRaw,
				text:     content,
				hasText:  hasText,
				terminal: choice["finish_reason"] != nil,
			}
			flushOwner := delta
			flushFrame := frame
			part.flush = func(restored string) {
				flushOwner["content"] = restored
				flushFrame.changed = true
			}
			batch.addPart(part)

			if rawToolCalls, ok := delta["tool_calls"].([]any); ok {
				for _, rawToolCall := range rawToolCalls {
					toolCall := rawToolCall.(map[string]any)
					function, ok := toolCall["function"].(map[string]any)
					if !ok {
						continue
					}
					arguments, ok := function["arguments"].(string)
					if !ok {
						continue
					}
					channel := ""
					if toolIndex, ok := nonnegativeJSONIndex(toolCall["index"]); ok {
						channel = "argument:openai:choice:" + strconv.FormatInt(choiceIndex, 10) + ":tool:" + strconv.FormatInt(toolIndex, 10)
					}
					batch.argumentOps = append(batch.argumentOps, semanticArgumentOp{part: &semanticArgumentPart{
						frame: frame, channel: channel, owner: function, field: "arguments",
						original: function["arguments"], text: arguments,
					}})
				}
			}
			if choice["finish_reason"] != nil {
				prefix := "argument:openai:choice:" + strconv.FormatInt(choiceIndex, 10) + ":tool:"
				batch.argumentOps = append(batch.argumentOps, semanticArgumentOp{terminal: openAIChatArgumentTerminal(frame, prefix)})
			}
		}
	}
	return batch
}

func parseOpenAIChatFrames(data []byte) []*semanticFrame {
	if frames := parseSemanticSSEFrames(data); len(frames) > 0 {
		return frames
	}
	doc, ok := decodeOneJSON(data)
	if !ok {
		return nil
	}
	return []*semanticFrame{{
		start:        0,
		next:         len(data),
		payloadStart: 0,
		payloadEnd:   len(data),
		framing:      semanticJSON,
		doc:          doc,
	}}
}

func openAIResponsesArgumentChannel(outputIndex int64, itemID string) string {
	return "argument:openai-response:output:" + strconv.FormatInt(outputIndex, 10) + ":item:" + base64.RawURLEncoding.EncodeToString([]byte(itemID))
}

func parseOpenAIResponsesArgumentChannel(channel string) (int64, string, bool) {
	const prefix = "argument:openai-response:output:"
	rest, ok := strings.CutPrefix(channel, prefix)
	if !ok {
		return 0, "", false
	}
	outputText, encodedItemID, ok := strings.Cut(rest, ":item:")
	if !ok || outputText == "" || encodedItemID == "" || strings.Contains(encodedItemID, ":") {
		return 0, "", false
	}
	for i := 0; i < len(outputText); i++ {
		if outputText[i] < '0' || outputText[i] > '9' {
			return 0, "", false
		}
	}
	outputIndex, err := strconv.ParseInt(outputText, 10, 64)
	if err != nil || outputIndex < 0 {
		return 0, "", false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encodedItemID)
	if err != nil || len(decoded) == 0 {
		return 0, "", false
	}
	return outputIndex, string(decoded), true
}

func openAIResponsesArgumentTerminal(frame *semanticFrame, channel, channelPrefix string, sequenceNumber any) *semanticArgumentTerminal {
	return &semanticArgumentTerminal{
		frame:         frame,
		channel:       channel,
		channelPrefix: channelPrefix,
		flush: func(flushedChannel, tail string) bool {
			outputIndex, itemID, ok := parseOpenAIResponsesArgumentChannel(flushedChannel)
			if !ok {
				return false
			}
			doc := map[string]any{
				"type":         "response.function_call_arguments.delta",
				"output_index": outputIndex,
				"item_id":      itemID,
				"delta":        tail,
			}
			if number, ok := sequenceNumber.(json.Number); ok {
				doc["sequence_number"] = number
			}
			frame.before = append(frame.before, semanticSynthetic{
				event: "response.function_call_arguments.delta",
				doc:   doc,
			})
			return true
		},
	}
}

// parseOpenAIResponsesSemantic adapts output text and function-call arguments
// to independent semantic channels while treating aggregate arguments atomically.
func parseOpenAIResponsesSemantic(data []byte) (*semanticBatch, bool) {
	batch := &semanticBatch{groups: make(map[string][]*semanticPart)}
	frames := parseSemanticSSEFrames(data)
	if len(frames) == 0 {
		if frame, ok := parseAtomicSemanticSSEFrame(data); ok {
			frames = []*semanticFrame{frame}
		}
	}
	for _, frame := range frames {
		root, ok := frame.doc.(map[string]any)
		if !ok {
			continue
		}
		eventType, ok := root["type"].(string)
		if !ok {
			continue
		}

		switch eventType {
		case "response.output_text.delta", "response.output_text.done":
			outputIndex, ok := nonnegativeJSONIndex(root["output_index"])
			if !ok {
				batch.addOpaqueFrame(frame)
				continue
			}
			contentIndex, ok := nonnegativeJSONIndex(root["content_index"])
			if !ok {
				batch.addOpaqueFrame(frame)
				continue
			}
			itemID := ""
			if rawItemID, exists := root["item_id"]; exists {
				var valid bool
				itemID, valid = rawItemID.(string)
				if !valid {
					batch.addOpaqueFrame(frame)
					continue
				}
			}
			if eventType == "response.output_text.delta" {
				if _, ok := root["delta"].(string); !ok {
					batch.addOpaqueFrame(frame)
					continue
				}
			} else if _, ok := root["text"].(string); !ok {
				batch.addOpaqueFrame(frame)
				continue
			}
			channel := "openai-response:output:" + strconv.FormatInt(outputIndex, 10) + ":content:" + strconv.FormatInt(contentIndex, 10)
			if itemID != "" {
				channel += ":item:" + itemID
			}

			part := &semanticPart{
				frame:   frame,
				channel: channel,
				owner:   root,
				field:   "delta",
			}
			if eventType == "response.output_text.delta" {
				delta := root["delta"].(string)
				part.original = root["delta"]
				part.text = delta
				part.hasText = true
			} else {
				part.terminal = true
				flushFrame := frame
				flushOutputIndex := root["output_index"]
				flushContentIndex := root["content_index"]
				optionalFields := make(map[string]any, 3)
				for _, field := range []string{"item_id", "sequence_number", "logprobs"} {
					if value, exists := root[field]; exists {
						optionalFields[field] = value
					}
				}
				part.flush = func(restored string) {
					doc := map[string]any{
						"type":          "response.output_text.delta",
						"output_index":  flushOutputIndex,
						"content_index": flushContentIndex,
						"delta":         restored,
					}
					for field, value := range optionalFields {
						doc[field] = value
					}
					flushFrame.before = append(flushFrame.before, semanticSynthetic{
						event: "response.output_text.delta",
						doc:   doc,
					})
				}
			}
			batch.frames = append(batch.frames, frame)
			batch.addPart(part)

		case "response.function_call_arguments.delta":
			outputIndex, indexOK := nonnegativeJSONIndex(root["output_index"])
			itemID, itemOK := root["item_id"].(string)
			delta, deltaOK := root["delta"].(string)
			if !indexOK || !itemOK || itemID == "" || !deltaOK {
				batch.addOpaqueFrame(frame)
				continue
			}
			batch.frames = append(batch.frames, frame)
			batch.argumentOps = append(batch.argumentOps, semanticArgumentOp{part: &semanticArgumentPart{
				frame: frame, channel: openAIResponsesArgumentChannel(outputIndex, itemID),
				owner: root, field: "delta", original: root["delta"], text: delta,
			}})

		case "response.function_call_arguments.done":
			outputIndex, indexOK := nonnegativeJSONIndex(root["output_index"])
			itemID, itemOK := root["item_id"].(string)
			arguments, argumentsOK := root["arguments"].(string)
			if !indexOK || !itemOK || itemID == "" || !argumentsOK {
				batch.addOpaqueFrame(frame)
				continue
			}
			batch.frames = append(batch.frames, frame)
			channel := openAIResponsesArgumentChannel(outputIndex, itemID)
			batch.argumentOps = append(batch.argumentOps, semanticArgumentOp{terminal: openAIResponsesArgumentTerminal(frame, channel, "", root["sequence_number"])})
			batch.atomicArguments = append(batch.atomicArguments, &semanticAtomicArgument{
				frame: frame, owner: root, field: "arguments", original: root["arguments"], text: arguments,
			})

		case "response.output_item.done":
			item, itemOK := root["item"].(map[string]any)
			if !itemOK {
				batch.addOpaqueFrame(frame)
				continue
			}
			itemType, typeOK := item["type"].(string)
			if !typeOK {
				batch.addOpaqueFrame(frame)
				continue
			}
			if itemType != "function_call" {
				continue
			}
			outputIndex, indexOK := nonnegativeJSONIndex(root["output_index"])
			itemID, idOK := item["id"].(string)
			arguments, argumentsOK := item["arguments"].(string)
			if !indexOK || !idOK || itemID == "" || !argumentsOK {
				batch.addOpaqueFrame(frame)
				continue
			}
			batch.frames = append(batch.frames, frame)
			channel := openAIResponsesArgumentChannel(outputIndex, itemID)
			batch.argumentOps = append(batch.argumentOps, semanticArgumentOp{terminal: openAIResponsesArgumentTerminal(frame, channel, "", root["sequence_number"])})
			batch.atomicArguments = append(batch.atomicArguments, &semanticAtomicArgument{
				frame: frame, owner: item, field: "arguments", original: item["arguments"], text: arguments,
			})

		case "response.completed":
			batch.frames = append(batch.frames, frame)
			batch.argumentOps = append(batch.argumentOps, semanticArgumentOp{terminal: openAIResponsesArgumentTerminal(frame, "", "argument:openai-response:", root["sequence_number"])})
			response, ok := root["response"].(map[string]any)
			if !ok {
				continue
			}
			output, ok := response["output"].([]any)
			if !ok {
				continue
			}
			for _, rawItem := range output {
				item, ok := rawItem.(map[string]any)
				if !ok {
					continue
				}
				itemType, _ := item["type"].(string)
				arguments, argumentsOK := item["arguments"].(string)
				if itemType != "function_call" || !argumentsOK {
					continue
				}
				batch.atomicArguments = append(batch.atomicArguments, &semanticAtomicArgument{
					frame: frame, owner: item, field: "arguments", original: item["arguments"], text: arguments,
				})
			}
		}
	}
	return batch, len(batch.frames) > 0
}

func claudeArgumentTerminal(frame *semanticFrame, channel, channelPrefix string) *semanticArgumentTerminal {
	return &semanticArgumentTerminal{
		frame:         frame,
		channel:       channel,
		channelPrefix: channelPrefix,
		flush: func(flushedChannel, tail string) bool {
			const prefix = "argument:claude:block:"
			indexText, ok := strings.CutPrefix(flushedChannel, prefix)
			if !ok || indexText == "" || strings.Contains(indexText, ":") {
				return false
			}
			blockIndex, err := strconv.ParseInt(indexText, 10, 64)
			if err != nil || blockIndex < 0 {
				return false
			}
			frame.before = append(frame.before, semanticSynthetic{
				event: "content_block_delta",
				doc: map[string]any{
					"type":  "content_block_delta",
					"index": blockIndex,
					"delta": map[string]any{
						"type":         "input_json_delta",
						"partial_json": tail,
					},
				},
			})
			return true
		},
	}
}

// parseClaudeSemantic adapts visible text and tool-input deltas to independent
// channels. Thinking deltas remain outside semantic pending state.
func parseClaudeSemantic(data []byte) (*semanticBatch, bool) {
	batch := &semanticBatch{groups: make(map[string][]*semanticPart)}
	for _, frame := range parseSemanticSSEFrames(data) {
		root, ok := frame.doc.(map[string]any)
		if !ok {
			continue
		}
		eventType, ok := root["type"].(string)
		if !ok || (eventType != "content_block_delta" && eventType != "content_block_stop" && eventType != "message_stop") {
			continue
		}
		if eventType == "message_stop" {
			batch.frames = append(batch.frames, frame)
			batch.argumentOps = append(batch.argumentOps, semanticArgumentOp{terminal: claudeArgumentTerminal(frame, "", "argument:claude:")})
			continue
		}
		index, ok := nonnegativeJSONIndex(root["index"])
		if !ok {
			batch.addOpaqueFrame(frame)
			continue
		}
		channel := "claude:block:" + strconv.FormatInt(index, 10)
		if eventType == "content_block_delta" {
			delta, ok := root["delta"].(map[string]any)
			if !ok {
				batch.addOpaqueFrame(frame)
				continue
			}
			deltaType, ok := delta["type"].(string)
			if !ok {
				batch.addOpaqueFrame(frame)
				continue
			}
			switch deltaType {
			case "text_delta":
				text, ok := delta["text"].(string)
				if !ok {
					batch.addOpaqueFrame(frame)
					continue
				}
				part := &semanticPart{
					frame: frame, channel: channel, owner: delta, field: "text",
					original: delta["text"], text: text, hasText: true,
				}
				batch.frames = append(batch.frames, frame)
				batch.addPart(part)
			case "input_json_delta":
				partialJSON, ok := delta["partial_json"].(string)
				if !ok {
					batch.addOpaqueFrame(frame)
					continue
				}
				batch.frames = append(batch.frames, frame)
				batch.argumentOps = append(batch.argumentOps, semanticArgumentOp{part: &semanticArgumentPart{
					frame: frame, channel: "argument:" + channel, owner: delta, field: "partial_json",
					original: delta["partial_json"], text: partialJSON,
				}})
			default:
				continue
			}
			continue
		}

		part := &semanticPart{frame: frame, channel: channel, terminal: true}
		{
			flushFrame := frame
			flushIndex := root["index"]
			part.flush = func(restored string) {
				flushFrame.before = append(flushFrame.before, semanticSynthetic{
					event: "content_block_delta",
					doc: map[string]any{
						"type":  "content_block_delta",
						"index": flushIndex,
						"delta": map[string]any{
							"type": "text_delta",
							"text": restored,
						},
					},
				})
			}
		}
		batch.frames = append(batch.frames, frame)
		batch.addPart(part)
		batch.argumentOps = append(batch.argumentOps, semanticArgumentOp{terminal: claudeArgumentTerminal(frame, "argument:"+channel, "")})
	}
	return batch, len(batch.frames) > 0
}

// parseGeminiSemantic adapts complete Gemini response documents delivered with
// an SSE media type. The dispatcher supplies the separate formatGemini gate.
func parseGeminiSemantic(data []byte, mediaType string) (*semanticBatch, bool) {
	if !strings.EqualFold(mediaType, "text/event-stream") {
		return nil, false
	}
	if batch, ok := parseGeminiFrames(parseSemanticSSEFrames(data)); ok {
		return batch, true
	}
	doc, ok := decodeOneJSON(data)
	if !ok {
		return nil, false
	}
	frame := &semanticFrame{
		start:        0,
		next:         len(data),
		payloadStart: 0,
		payloadEnd:   len(data),
		framing:      semanticJSON,
		doc:          doc,
	}
	return parseGeminiFrames([]*semanticFrame{frame})
}

func parseGeminiFrames(frames []*semanticFrame) (*semanticBatch, bool) {
	batch := &semanticBatch{groups: make(map[string][]*semanticPart)}
	for _, frame := range frames {
		root, ok := frame.doc.(map[string]any)
		if !ok {
			continue
		}
		rawCandidates, exists := root["candidates"]
		if !exists {
			continue
		}
		candidates, ok := rawCandidates.([]any)
		if !ok {
			batch.addOpaqueFrame(frame)
			continue
		}
		valid := true
		for _, rawCandidate := range candidates {
			candidate, ok := rawCandidate.(map[string]any)
			if !ok {
				valid = false
				break
			}
			if rawIndex, exists := candidate["index"]; exists {
				if _, ok := nonnegativeJSONIndex(rawIndex); !ok {
					valid = false
					break
				}
			}
			if finishReason, exists := candidate["finishReason"]; exists && finishReason != nil {
				if _, ok := finishReason.(string); !ok {
					valid = false
					break
				}
			}
			rawContent, exists := candidate["content"]
			if !exists {
				continue
			}
			content, ok := rawContent.(map[string]any)
			if !ok {
				valid = false
				break
			}
			rawParts, exists := content["parts"]
			if !exists {
				continue
			}
			parts, ok := rawParts.([]any)
			if !ok {
				valid = false
				break
			}
			for _, rawPart := range parts {
				part, ok := rawPart.(map[string]any)
				if !ok {
					valid = false
					break
				}
				thought := false
				if rawThought, exists := part["thought"]; exists {
					thought, ok = rawThought.(bool)
					if !ok {
						valid = false
						break
					}
				}
				if thought {
					continue
				}
				if text, exists := part["text"]; exists {
					if _, ok := text.(string); !ok {
						valid = false
						break
					}
				}
			}
			if !valid {
				break
			}
		}
		if !valid {
			batch.addOpaqueFrame(frame)
			continue
		}
		batch.frames = append(batch.frames, frame)
		for _, rawCandidate := range candidates {
			candidate, _ := rawCandidate.(map[string]any)
			content, _ := candidate["content"].(map[string]any)
			parts, _ := content["parts"].([]any)
			for _, rawPart := range parts {
				part, _ := rawPart.(map[string]any)
				if thought, _ := part["thought"].(bool); !thought {
					continue
				}
				if text, exists := part["text"]; exists {
					batch.excluded = append(batch.excluded, &semanticPart{
						frame: frame, owner: part, field: "text", original: text,
					})
				}
			}
		}
		for candidatePosition, rawCandidate := range candidates {
			candidate, ok := rawCandidate.(map[string]any)
			if !ok {
				continue
			}
			candidateIndex := strconv.Itoa(candidatePosition)
			if rawIndex, exists := candidate["index"]; exists {
				index, ok := nonnegativeJSONIndex(rawIndex)
				if !ok {
					continue
				}
				candidateIndex = strconv.FormatInt(index, 10)
			}
			finishReason, _ := candidate["finishReason"].(string)
			if finishReason != "" {
				terminalCandidate := candidate
				terminalFrame := frame
				batch.terminals = append(batch.terminals, &semanticTerminal{
					channelPrefix: "gemini:candidate:" + candidateIndex + ":part:",
					flush: func(restored string) bool {
						contentRaw, contentExists := terminalCandidate["content"]
						content, contentOK := contentRaw.(map[string]any)
						if contentExists && !contentOK {
							return false
						}
						if !contentExists {
							content = make(map[string]any)
							terminalCandidate["content"] = content
						}

						partsRaw, partsExist := content["parts"]
						parts, partsOK := partsRaw.([]any)
						if partsExist && !partsOK {
							return false
						}
						content["parts"] = append(parts, map[string]any{"text": restored})
						terminalFrame.changed = true
						return true
					},
				})
			}
			content, ok := candidate["content"].(map[string]any)
			if !ok {
				continue
			}
			parts, ok := content["parts"].([]any)
			if !ok {
				continue
			}
			for partPosition, rawPart := range parts {
				partOwner, ok := rawPart.(map[string]any)
				if !ok {
					continue
				}
				if thought, _ := partOwner["thought"].(bool); thought {
					continue
				}
				text, ok := partOwner["text"].(string)
				if !ok {
					continue
				}
				channel := "gemini:candidate:" + candidateIndex + ":part:" + strconv.Itoa(partPosition)
				part := &semanticPart{
					frame:    frame,
					channel:  channel,
					owner:    partOwner,
					field:    "text",
					original: partOwner["text"],
					text:     text,
					hasText:  true,
					terminal: finishReason != "",
				}
				batch.addPart(part)
			}
		}
	}
	return batch, len(batch.frames) > 0
}

// rewriteSemanticParts restores complete tokens and retains only a possible
// trailing token prefix for each protocol-qualified semantic channel.
func (s *streamStore) rewriteSemanticParts(key string, groups map[string][]*semanticPart, tokenRe *regexp.Regexp, labels []string, allowed map[string]struct{}, v *vault) {
	s.rewriteSemanticPartsWithTerminals(key, groups, nil, nil, tokenRe, labels, allowed, v)
}

func (s *streamStore) rewriteSemanticPartsWithTerminals(key string, groups map[string][]*semanticPart, channelOrder []string, terminals []*semanticTerminal, tokenRe *regexp.Regexp, labels []string, allowed map[string]struct{}, v *vault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.purgeLocked(now)
	e := s.getOrCreateLocked(key, now)
	if e.content == nil {
		e.content = make(map[string]string)
	}
	s.resizeEntryLocked(e)
	entryBytes := e.bytes
	orderedChannels := append([]string(nil), channelOrder...)
	seen := make(map[string]struct{}, len(orderedChannels))
	for _, channel := range orderedChannels {
		seen[channel] = struct{}{}
	}
	var remainingChannels []string
	for channel := range groups {
		if _, exists := seen[channel]; !exists {
			remainingChannels = append(remainingChannels, channel)
		}
	}
	sort.Strings(remainingChannels)
	orderedChannels = append(orderedChannels, remainingChannels...)
	for _, channel := range orderedChannels {
		parts, exists := groups[channel]
		if !exists {
			continue
		}
		storedPending, channelExists := e.content[channel]
		pending := storedPending
		channelBaseBytes := entryBytes
		if channelExists {
			channelBaseBytes -= len(channel) + len(storedPending)
		}
		for _, part := range parts {
			if !part.hasText {
				if !part.terminal || pending == "" {
					continue
				}
			}
			combined := pending + part.text
			hold := incompleteTokenTailForLabels([]byte(combined), labels)
			if part.terminal {
				hold = 0
			}
			emit := combined[:len(combined)-hold]
			restored := string(restoreRaw([]byte(emit), tokenRe, allowed, v))
			nextPending := combined[len(combined)-hold:]
			if nextPending != "" {
				if _, exists := e.content[channel]; !exists && streamEntryChannelCount(e) >= streamAllowlistMaxTokens {
					restored += nextPending
					nextPending = ""
				} else if channelBaseBytes+len(channel)+len(nextPending) > s.maxBytes {
					restored += nextPending
					nextPending = ""
				}
			}
			if part.hasText {
				if restored != part.text {
					part.owner[part.field] = restored
					part.frame.changed = true
				}
			} else if pending != "" {
				if part.flush != nil {
					part.flush(restored)
				} else {
					part.owner[part.field] = restored
					part.frame.changed = true
				}
			}
			pending = nextPending
		}
		if pending == "" {
			delete(e.content, channel)
		} else {
			e.content[channel] = pending
		}
		entryBytes = channelBaseBytes
		if pending != "" {
			entryBytes += len(channel) + len(pending)
		}
	}
	for _, terminal := range terminals {
		type pendingChannel struct {
			name     string
			position int
		}
		var pendingChannels []pendingChannel
		for channel := range e.content {
			if !strings.HasPrefix(channel, terminal.channelPrefix) {
				continue
			}
			position, err := strconv.Atoi(strings.TrimPrefix(channel, terminal.channelPrefix))
			if err != nil || position < 0 {
				continue
			}
			pendingChannels = append(pendingChannels, pendingChannel{name: channel, position: position})
		}
		sort.Slice(pendingChannels, func(i, j int) bool {
			if pendingChannels[i].position == pendingChannels[j].position {
				return pendingChannels[i].name < pendingChannels[j].name
			}
			return pendingChannels[i].position < pendingChannels[j].position
		})
		for _, channel := range pendingChannels {
			pending := e.content[channel.name]
			restored := string(restoreRaw([]byte(pending), tokenRe, allowed, v))
			if terminal.flush != nil && terminal.flush(restored) {
				delete(e.content, channel.name)
			}
		}
	}
	s.resizeEntryLocked(e)
	s.evictBytesLocked(e)
	s.touchLocked(e, now)
}

func (s *streamStore) rewriteJSONArgumentOps(key string, ops []semanticArgumentOp, tokenRe *regexp.Regexp, labels []string, allowed map[string]struct{}, v *vault) {
	if len(ops) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.purgeLocked(now)
	e := s.getOrCreateLocked(key, now)
	if e.arguments == nil {
		e.arguments = make(map[string]jsonArgumentState)
	}
	s.resizeEntryLocked(e)

	writePart := func(part *semanticArgumentPart, output string) {
		if output == part.text {
			return
		}
		part.owner[part.field] = output
		part.frame.changed = true
	}
	rewriteAtomic := func(part *semanticArgumentPart) {
		restored, changed := restoreAtomicJSONArgument(part.text, tokenRe, labels, allowed, v)
		if changed {
			part.owner[part.field] = restored
			part.frame.changed = true
		}
	}
	setOverflow := func() {
		if !e.argumentOverflow {
			if len(e.arguments) == 0 && e.bytes+1 > s.maxBytes {
				return
			}
			e.argumentOverflow = true
			s.resizeEntryLocked(e)
		}
	}
	partsByFrame := make(map[*semanticFrame]map[string]*semanticArgumentPart)

	for _, op := range ops {
		if part := op.part; part != nil {
			if part.channel == "" {
				rewriteAtomic(part)
				continue
			}
			frameParts := partsByFrame[part.frame]
			if frameParts == nil {
				frameParts = make(map[string]*semanticArgumentPart)
				partsByFrame[part.frame] = frameParts
			}
			frameParts[part.channel] = part

			prior, exists := e.arguments[part.channel]
			if !exists && e.argumentOverflow {
				rewriteAtomic(part)
				continue
			}
			if !exists && streamEntryChannelCount(e) >= streamAllowlistMaxTokens {
				setOverflow()
				continue
			}

			output, next := rewriteJSONArgumentFragment(part.text, prior, tokenRe, labels, allowed, v, false)
			candidateBytes := e.bytes + len(part.channel) + jsonArgumentStateBytes(next)
			if exists {
				candidateBytes -= len(part.channel) + jsonArgumentStateBytes(prior)
			} else if len(e.arguments) == 0 && !e.argumentOverflow {
				candidateBytes++
			}
			if candidateBytes > s.maxBytes {
				if !exists {
					setOverflow()
					continue
				}
				writePart(part, prior.tail+part.text)
				e.arguments[part.channel] = jsonArgumentState{disabled: true}
				s.resizeEntryLocked(e)
				continue
			}

			writePart(part, output)
			e.arguments[part.channel] = next
			s.resizeEntryLocked(e)
			continue
		}

		terminal := op.terminal
		if terminal == nil {
			continue
		}
		var channels []string
		if terminal.channel != "" {
			if _, exists := e.arguments[terminal.channel]; exists {
				channels = append(channels, terminal.channel)
			}
		} else {
			for channel := range e.arguments {
				if strings.HasPrefix(channel, terminal.channelPrefix) {
					channels = append(channels, channel)
				}
			}
			sort.Strings(channels)
		}
		for _, channel := range channels {
			state := e.arguments[channel]
			output, _ := rewriteJSONArgumentFragment("", state, tokenRe, labels, allowed, v, true)
			if part := partsByFrame[terminal.frame][channel]; part != nil {
				current, _ := part.owner[part.field].(string)
				if output != "" {
					part.owner[part.field] = current + output
					part.frame.changed = true
				}
				delete(e.arguments, channel)
				s.resizeEntryLocked(e)
				continue
			}
			if output == "" {
				delete(e.arguments, channel)
				s.resizeEntryLocked(e)
				continue
			}
			if terminal.flush != nil && terminal.flush(channel, output) {
				delete(e.arguments, channel)
				s.resizeEntryLocked(e)
			}
		}
	}

	s.resizeEntryLocked(e)
	s.evictBytesLocked(e)
	s.touchLocked(e, now)
}

func encodeSemanticJSON(doc any) ([]byte, bool) {
	var payload bytes.Buffer
	enc := json.NewEncoder(&payload)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, false
	}
	return bytes.TrimSuffix(payload.Bytes(), []byte{'\n'}), true
}

// renderSemanticFrames replaces only changed JSON payload spans. Every gap is
// still passed through generic SSE restoration so mixed event streams retain
// the existing behavior.
func renderSemanticFrames(data []byte, frames []*semanticFrame, tokenRe *regexp.Regexp, allowed map[string]struct{}, v *vault) []byte {
	ordered := append([]*semanticFrame(nil), frames...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].start < ordered[j].start })

	var out bytes.Buffer
	out.Grow(len(data))
	cursor := 0
	for _, frame := range ordered {
		if frame.start < cursor || frame.next > len(data) {
			return data
		}
		out.Write(restoreSSE(data[cursor:frame.start], tokenRe, allowed, v))
		for _, synthetic := range frame.before {
			payload, ok := encodeSemanticJSON(synthetic.doc)
			if !ok {
				return data
			}
			if synthetic.event != "" {
				out.WriteString("event: ")
				out.WriteString(synthetic.event)
				out.Write(frame.lineEnding)
			}
			out.WriteString("data:")
			out.Write(frame.dataLead)
			out.Write(payload)
			out.Write(frame.lineEnding)
			out.Write(frame.lineEnding)
		}
		if !frame.changed {
			out.Write(data[frame.start:frame.next])
			cursor = frame.next
			continue
		}
		payload, ok := encodeSemanticJSON(frame.doc)
		if !ok {
			return data
		}
		out.Write(data[frame.start:frame.payloadStart])
		out.Write(payload)
		out.Write(data[frame.payloadEnd:frame.next])
		cursor = frame.next
	}
	out.Write(restoreSSE(data[cursor:], tokenRe, allowed, v))
	return out.Bytes()
}

// restoreSemanticStream dispatches only protocols whose semantic stream shape
// is explicitly supported. Other formats fall through to generic restoration.
func restoreSemanticStream(key string, data []byte, tokenRe *regexp.Regexp, labels []string, allowed map[string]struct{}, v *vault, mediaType, sourceFormat string) ([]byte, bool) {
	if !strings.EqualFold(mediaType, "text/event-stream") {
		return nil, false
	}
	var batch semanticBatch
	switch sourceFormat {
	case formatOpenAI:
		batch = parseOpenAIChatSemantic(parseOpenAIChatFrames(data))
	case formatOpenAIResponse:
		parsed, ok := parseOpenAIResponsesSemantic(data)
		if !ok {
			return nil, false
		}
		batch = *parsed
	case formatClaude:
		parsed, ok := parseClaudeSemantic(data)
		if !ok {
			return nil, false
		}
		batch = *parsed
	case formatGemini:
		parsed, ok := parseGeminiSemantic(data, mediaType)
		if !ok {
			return nil, false
		}
		batch = *parsed
	default:
		return nil, false
	}
	if len(batch.frames) == 0 {
		return nil, false
	}
	if tokenRe == nil || v == nil {
		return data, true
	}

	partsByFrame := make(map[*semanticFrame][]*semanticPart, len(batch.frames))
	for _, channel := range batch.channelOrder {
		for _, part := range batch.groups[channel] {
			partsByFrame[part.frame] = append(partsByFrame[part.frame], part)
		}
	}
	for _, part := range batch.excluded {
		partsByFrame[part.frame] = append(partsByFrame[part.frame], part)
	}
	type argumentField struct {
		frame    *semanticFrame
		owner    map[string]any
		field    string
		original any
	}
	argumentFieldsByFrame := make(map[*semanticFrame][]argumentField, len(batch.frames))
	for _, op := range batch.argumentOps {
		if op.part != nil {
			part := op.part
			argumentFieldsByFrame[part.frame] = append(argumentFieldsByFrame[part.frame], argumentField{
				frame: part.frame, owner: part.owner, field: part.field, original: part.original,
			})
		}
	}
	for _, part := range batch.atomicArguments {
		argumentFieldsByFrame[part.frame] = append(argumentFieldsByFrame[part.frame], argumentField{
			frame: part.frame, owner: part.owner, field: part.field, original: part.original,
		})
	}
	for _, frame := range batch.frames {
		if frame.opaque {
			continue
		}
		type removedField struct {
			part  *semanticPart
			value any
		}
		var removed []removedField
		for _, part := range partsByFrame[frame] {
			if value, exists := part.owner[part.field]; exists {
				removed = append(removed, removedField{part: part, value: value})
				delete(part.owner, part.field)
			}
		}
		for _, field := range argumentFieldsByFrame[frame] {
			if _, exists := field.owner[field.field]; exists {
				delete(field.owner, field.field)
			}
		}
		r := &restorer{tokenRe: tokenRe, allowed: allowed, v: v}
		r.walk(frame.doc)
		if r.changed {
			frame.changed = true
		}
		for _, field := range removed {
			field.part.owner[field.part.field] = field.value
		}
		for _, field := range argumentFieldsByFrame[frame] {
			field.owner[field.field] = field.original
		}
	}
	for _, field := range batch.atomicArguments {
		restored, changed := restoreAtomicJSONArgument(field.text, tokenRe, labels, allowed, v)
		field.owner[field.field] = restored
		if changed {
			field.frame.changed = true
		}
	}
	streamCarry.rewriteJSONArgumentOps(key, batch.argumentOps, tokenRe, labels, allowed, v)
	streamCarry.rewriteSemanticPartsWithTerminals(key, batch.groups, batch.channelOrder, batch.terminals, tokenRe, labels, allowed, v)
	return renderSemanticFrames(data, batch.frames, tokenRe, allowed, v), true
}
