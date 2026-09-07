package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

func detokTestSetup() (string, *regexp.Regexp) {
	setSharedVault(newVault(100, time.Hour))
	label := "REDACTED"
	return label, tokenPattern(label)
}

func TestRewriteJSONArgumentFragmentAtEveryTokenSplit(t *testing.T) {
	label := "REDACTED"
	tokenRe := tokenPattern(label)
	secret := "quote=\" slash=\\ line=\n tab=\t control=\x01 unicode=世界 html=<>&"
	token := makeToken(label, secret)
	allowed := map[string]struct{}{token: {}}

	for _, encodedToken := range []string{
		token,
		strings.ReplaceAll(strings.ReplaceAll(token, "<", `\u003c`), ">", `\u003e`),
		strings.ReplaceAll(strings.ReplaceAll(token, "<", `\u003C`), ">", `\u003E`),
	} {
		arguments := `{"value":"` + encodedToken + `"}`
		for split := 0; split <= len(arguments); split++ {
			v := newVault(4, time.Hour)
			v.Put(token, secret)
			first, state := rewriteJSONArgumentFragment(arguments[:split], jsonArgumentState{}, tokenRe, []string{label}, allowed, v, false)
			second, state := rewriteJSONArgumentFragment(arguments[split:], state, tokenRe, []string{label}, allowed, v, true)
			if state.tail != "" {
				t.Fatalf("representation %q split %d retained tail %q", encodedToken, split, state.tail)
			}
			var got map[string]string
			if err := json.Unmarshal([]byte(first+second), &got); err != nil {
				t.Fatalf("representation %q split %d produced invalid JSON %q: %v", encodedToken, split, first+second, err)
			}
			if got["value"] != secret {
				t.Fatalf("representation %q split %d value = %q, want %q", encodedToken, split, got["value"], secret)
			}
		}
	}
}

func TestRewriteJSONArgumentFragmentFocusedCases(t *testing.T) {
	label := "REDACTED"
	tokenRe := tokenPattern(label)

	t.Run("escaped delimiter case combinations", func(t *testing.T) {
		secret := "secret"
		token := makeToken(label, secret)
		for _, opening := range []byte{'c', 'C'} {
			for _, closing := range []byte{'e', 'E'} {
				encodedToken := `\u003` + string(opening) + token[1:len(token)-1] + `\u003` + string(closing)
				argument := `{"value":"` + encodedToken + `"}`
				v := newVault(1, time.Hour)
				v.Put(token, secret)
				got, _ := rewriteJSONArgumentFragment(argument, jsonArgumentState{}, tokenRe, []string{label}, map[string]struct{}{token: {}}, v, true)
				if got != `{"value":"secret"}` {
					t.Fatalf("delimiters %c/%c restored to %q", opening, closing, got)
				}
			}
		}
	})

	t.Run("multiple tokens", func(t *testing.T) {
		firstToken := makeToken(label, "first")
		secondToken := makeToken(label, "second")
		argument := `{"values":["` + firstToken + `","` + secondToken + `"]}`
		v := newVault(2, time.Hour)
		v.Put(firstToken, "first")
		v.Put(secondToken, "second")
		allowed := map[string]struct{}{firstToken: {}, secondToken: {}}
		got, _ := rewriteJSONArgumentFragment(argument, jsonArgumentState{}, tokenRe, []string{label}, allowed, v, true)
		if got != `{"values":["first","second"]}` {
			t.Fatalf("multiple token restoration = %q", got)
		}
	})

	t.Run("object key", func(t *testing.T) {
		token := makeToken(label, "restored-key")
		argument := `{"` + token + `":"value"}`
		v := newVault(1, time.Hour)
		v.Put(token, "restored-key")
		got, _ := rewriteJSONArgumentFragment(argument, jsonArgumentState{}, tokenRe, []string{label}, map[string]struct{}{token: {}}, v, true)
		if got != `{"restored-key":"value"}` {
			t.Fatalf("object key restoration = %q", got)
		}
	})

	t.Run("embedded in larger string", func(t *testing.T) {
		token := makeToken(label, "middle")
		argument := `{"value":"before ` + token + ` after"}`
		v := newVault(1, time.Hour)
		v.Put(token, "middle")
		got, _ := rewriteJSONArgumentFragment(argument, jsonArgumentState{}, tokenRe, []string{label}, map[string]struct{}{token: {}}, v, true)
		if got != `{"value":"before middle after"}` {
			t.Fatalf("embedded token restoration = %q", got)
		}
	})

	t.Run("restored secret is not rescanned", func(t *testing.T) {
		innerToken := makeToken(label, "inner-secret")
		outerSecret := "contains " + innerToken
		outerToken := makeToken(label, outerSecret)
		argument := `{"value":"` + outerToken + `"}`
		v := newVault(2, time.Hour)
		v.Put(innerToken, "inner-secret")
		v.Put(outerToken, outerSecret)
		allowed := map[string]struct{}{innerToken: {}, outerToken: {}}
		got, _ := rewriteJSONArgumentFragment(argument, jsonArgumentState{}, tokenRe, []string{label}, allowed, v, true)
		if got != `{"value":"contains `+innerToken+`"}` {
			t.Fatalf("restored secret was rescanned: %q", got)
		}
	})

	t.Run("outside JSON string", func(t *testing.T) {
		token := makeToken(label, "secret")
		argument := `123 ` + token
		v := newVault(1, time.Hour)
		v.Put(token, "secret")
		got, _ := rewriteJSONArgumentFragment(argument, jsonArgumentState{}, tokenRe, []string{label}, map[string]struct{}{token: {}}, v, true)
		if got != argument {
			t.Fatalf("token outside string changed: %q", got)
		}
	})

	t.Run("invalid escape split disables channel", func(t *testing.T) {
		token := makeToken(label, "secret")
		firstFragment := `{"value":"bad\`
		secondFragment := `q` + token + `"}`
		v := newVault(1, time.Hour)
		v.Put(token, "secret")
		first, state := rewriteJSONArgumentFragment(firstFragment, jsonArgumentState{}, tokenRe, []string{label}, map[string]struct{}{token: {}}, v, false)
		second, state := rewriteJSONArgumentFragment(secondFragment, state, tokenRe, []string{label}, map[string]struct{}{token: {}}, v, true)
		if !state.disabled {
			t.Fatal("invalid escape did not disable channel")
		}
		if state.tail != "" {
			t.Fatalf("disabled channel retained tail %q", state.tail)
		}
		if got := first + second; got != firstFragment+secondFragment {
			t.Fatalf("invalid source changed: got %q want %q", got, firstFragment+secondFragment)
		}
	})

	t.Run("disabled channel emits retained bytes", func(t *testing.T) {
		got, state := rewriteJSONArgumentFragment("fragment", jsonArgumentState{tail: "retained", disabled: true}, tokenRe, []string{label}, nil, nil, false)
		if got != "retainedfragment" {
			t.Fatalf("disabled channel output = %q, want %q", got, "retainedfragment")
		}
		if !state.disabled || state.tail != "" {
			t.Fatalf("disabled channel state = %+v", state)
		}
	})

	t.Run("escaped gate misses preserve bytes", func(t *testing.T) {
		token := makeToken(label, "secret")
		argument := `{"value":"\u003C` + token[1:len(token)-1] + `\u003e"}`
		tests := []struct {
			name    string
			allowed map[string]struct{}
			vault   *vault
		}{
			{name: "vault", allowed: map[string]struct{}{token: {}}, vault: newVault(1, time.Hour)},
			{name: "allowlist", allowed: nil, vault: func() *vault {
				v := newVault(1, time.Hour)
				v.Put(token, "secret")
				return v
			}()},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				got, _ := rewriteJSONArgumentFragment(argument, jsonArgumentState{}, tokenRe, []string{label}, test.allowed, test.vault, true)
				if got != argument {
					t.Fatalf("gate miss changed escaped token: got %q want %q", got, argument)
				}
			})
		}
	})
}

func TestRewriteJSONArgumentFragmentRequiresBothGates(t *testing.T) {
	label := "REDACTED"
	tokenRe := tokenPattern(label)
	token := makeToken(label, "secret")
	argument := `{"value":"` + token + `"}`

	vaultMiss, _ := rewriteJSONArgumentFragment(argument, jsonArgumentState{}, tokenRe, []string{label}, map[string]struct{}{token: {}}, newVault(1, time.Hour), true)
	if vaultMiss != argument {
		t.Fatalf("vault miss changed argument: %q", vaultMiss)
	}

	v := newVault(1, time.Hour)
	v.Put(token, "secret")
	allowlistMiss, _ := rewriteJSONArgumentFragment(argument, jsonArgumentState{}, tokenRe, []string{label}, nil, v, true)
	if allowlistMiss != argument {
		t.Fatalf("allowlist miss changed argument: %q", allowlistMiss)
	}
}

func TestRewriteJSONArgumentFragmentVaultExpiryBetweenFragments(t *testing.T) {
	label := "REDACTED"
	tokenRe := tokenPattern(label)
	token := makeToken(label, "secret")
	argument := `{"value":"` + token + `"}`
	split := strings.Index(argument, token) + len(token)/2
	v := newVault(1, time.Hour)
	v.Put(token, "secret")

	first, state := rewriteJSONArgumentFragment(argument[:split], jsonArgumentState{}, tokenRe, []string{label}, map[string]struct{}{token: {}}, v, false)
	v.mu.Lock()
	v.items[token].Value.(*vaultEntry).expiresAt = time.Now().Add(-time.Second)
	v.mu.Unlock()
	second, state := rewriteJSONArgumentFragment(argument[split:], state, tokenRe, []string{label}, map[string]struct{}{token: {}}, v, true)
	if state.tail != "" {
		t.Fatalf("expiry retained tail %q", state.tail)
	}
	if got := first + second; got != argument {
		t.Fatalf("expired token changed: got %q want %q", got, argument)
	}
}

func TestRewriteJSONArgumentFragmentIsOnePass(t *testing.T) {
	label := "REDACTED"
	tokenRe := tokenPattern(label)
	innerToken := makeToken(label, "inner")
	outerSecret := "prefix " + innerToken + " suffix"
	outerToken := makeToken(label, outerSecret)
	argument := `{"value":"` + outerToken + `"}`
	v := newVault(2, time.Hour)
	v.Put(innerToken, "inner")
	v.Put(outerToken, outerSecret)
	allowed := map[string]struct{}{innerToken: {}, outerToken: {}}

	got, _ := rewriteJSONArgumentFragment(argument, jsonArgumentState{}, tokenRe, []string{label}, allowed, v, true)
	want := `{"value":"prefix ` + innerToken + ` suffix"}`
	if got != want {
		t.Fatalf("one-pass restoration = %q, want %q", got, want)
	}
}

func TestRewriteJSONArgumentFragmentStateBytes(t *testing.T) {
	state := jsonArgumentState{tail: "abc"}
	if got := jsonArgumentStateBytes(state); got != 11 {
		t.Fatalf("jsonArgumentStateBytes = %d, want 11", got)
	}
}

func TestStreamStoreByteAccountingIncludesArgumentState(t *testing.T) {
	store := newStreamStore()
	key := "stream"
	channel := "argument:openai:choice:0:tool:1"
	state := jsonArgumentState{tail: `\u003cREDACTED_1a2b`, disabled: true}

	store.mu.Lock()
	entry := store.getOrCreateLocked(key, time.Now())
	entry.arguments = map[string]jsonArgumentState{channel: state}
	store.resizeEntryLocked(entry)
	got := entry.bytes
	store.mu.Unlock()

	want := len(key) + len(channel) + jsonArgumentStateBytes(state) + 1
	if got != want {
		t.Fatalf("argument state bytes = %d, want %d", got, want)
	}
}

func TestRewriteJSONArgumentFragmentCopiesRetainedTail(t *testing.T) {
	label := "REDACTED"
	tokenRe := tokenPattern(label)
	token := makeToken(label, "secret")
	partial := token[:len(token)-1]
	largeValue := strings.Repeat("x", 1<<20)
	v := newVault(1, time.Hour)
	v.Put(token, "secret")
	allowed := map[string]struct{}{token: {}}

	for _, test := range []struct {
		name     string
		fragment string
	}{
		{name: "without match", fragment: `{"value":"` + largeValue + partial},
		{name: "with match", fragment: `{"value":"` + token + largeValue + partial},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, state := rewriteJSONArgumentFragment(test.fragment, jsonArgumentState{}, tokenRe, []string{label}, allowed, v, false)
			if state.tail != partial {
				t.Fatalf("retained tail = %q, want %q", state.tail, partial)
			}

			fragmentStart := uintptr(unsafe.Pointer(unsafe.StringData(test.fragment)))
			fragmentEnd := fragmentStart + uintptr(len(test.fragment))
			tailStart := uintptr(unsafe.Pointer(unsafe.StringData(state.tail)))
			if tailStart >= fragmentStart && tailStart < fragmentEnd {
				t.Fatalf("retained tail aliases %d-byte fragment backing storage", len(test.fragment))
			}
		})
	}
}

func TestRewriteJSONArgumentFragmentEscapedScanIsLinear(t *testing.T) {
	label := "REDACTED"
	tokenRe := tokenPattern(label)
	token := makeToken(label, "secret")
	encodedToken := strings.ReplaceAll(strings.ReplaceAll(token, "<", `\u003C`), ">", `\u003e`)
	repeatedOpenings := strings.Repeat(`\u003c`, 4096)
	argument := `{"value":"` + repeatedOpenings + encodedToken + `"}`

	work := 0
	matches := findJSONArgumentMatchesWithWork(argument, jsonArgumentLexState{}, tokenRe, &work)
	if len(matches) != 1 || matches[0].canonical != token {
		t.Fatalf("escaped matches = %+v, want only %q", matches, token)
	}
	if work > 4*len(argument) {
		t.Fatalf("escaped scan work = %d for %d bytes, want at most four operations per byte", work, len(argument))
	}
}

func TestRestoreAtomicJSONArgumentRejectsMalformedJSON(t *testing.T) {
	label, tokenRe := detokTestSetup()
	token := makeToken(label, "secret")
	getSharedVault().Put(token, "secret")
	malformed := `{"value":"` + token
	got, changed := restoreAtomicJSONArgument(malformed, tokenRe, []string{label}, map[string]struct{}{token: {}}, getSharedVault())
	if changed || got != malformed {
		t.Fatalf("malformed argument changed: changed=%v got=%q", changed, got)
	}
}

func TestRestoreAtomicJSONArgumentReportsByteChanges(t *testing.T) {
	label := "REDACTED"
	tokenRe := tokenPattern(label)
	token := makeToken(label, "secret")
	v := newVault(1, time.Hour)
	v.Put(token, "secret")
	allowed := map[string]struct{}{token: {}}

	restored, changed := restoreAtomicJSONArgument(`{"value":"`+token+`"}`, tokenRe, []string{label}, allowed, v)
	if !changed || restored != `{"value":"secret"}` {
		t.Fatalf("restored argument: changed=%v got=%q", changed, restored)
	}
	unchanged := `{"value":"plain"}`
	got, changed := restoreAtomicJSONArgument(unchanged, tokenRe, []string{label}, allowed, v)
	if changed || got != unchanged {
		t.Fatalf("unchanged argument: changed=%v got=%q", changed, got)
	}
}

func TestRestoreTokensLeavesUnknown(t *testing.T) {
	label, tokenRe := detokTestSetup()
	token := makeToken(label, "never-stored")
	// deliberately NOT Put into the vault
	body := []byte("value=" + token)
	out := string(restoreBody(body, tokenRe, nil, getSharedVault()))
	if out != "value="+token {
		t.Fatalf("unknown token should be left verbatim, got %q", out)
	}
}

func TestTokenLength(t *testing.T) {
	if got := tokenLength("REDACTED"); got != 27 {
		t.Fatalf("tokenLength(REDACTED) = %d, want 27", got)
	}
}

func TestIsTokenPrefix(t *testing.T) {
	label := "REDACTED"
	cases := []struct {
		in   string
		want bool
	}{
		{"<", true},
		{"<RED", true},
		{"<REDACTED_", true},
		{"<REDACTED_1a2b", true},
		{"<div", false},
		{"<NOTLABEL_123456", false},
		{"<REDACTED_z", false},                 // z is not hex
		{"<REDACTED_00000000000000000", false}, // 17 hex, too long
	}
	for _, c := range cases {
		if got := isTokenPrefix([]byte(c.in), label); got != c.want {
			t.Fatalf("isTokenPrefix(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestDetokenizeStreamSplitToken(t *testing.T) {
	label, tokenRe := detokTestSetup()
	original := "sk-abcdefghij0123456789"
	token := makeToken(label, original)
	getSharedVault().Put(token, original)

	req := []byte(`{"model":"x"}`)
	key := streamKey(req)

	half := len(token) / 2
	chunk1 := []byte("prefix " + token[:half])
	chunk2 := []byte(token[half:] + " suffix")

	out1b, _ := detokenizeStreamChunk(key, chunk1, tokenRe, []string{label}, nil, getSharedVault(), false)
	out1 := string(out1b)
	if !strings.Contains(out1, "prefix ") {
		t.Fatalf("out1 missing prefix: %q", out1)
	}
	if strings.Contains(out1, original) {
		t.Fatalf("out1 restored too early: %q", out1)
	}

	out2b, _ := detokenizeStreamChunk(key, chunk2, tokenRe, []string{label}, nil, getSharedVault(), false)
	out2 := string(out2b)
	combined := out1 + out2
	if !strings.Contains(combined, original) {
		t.Fatalf("combined did not restore original: %q", combined)
	}
	if strings.Contains(combined, token) {
		t.Fatalf("combined still contains raw token: %q", combined)
	}
}

func TestDetokenizeStreamNoFalseWithhold(t *testing.T) {
	label, tokenRe := detokTestSetup()
	req := []byte(`{"model":"y"}`)
	key := streamKey(req)

	chunk := []byte("<div>hello</div>")
	outb, _ := detokenizeStreamChunk(key, chunk, tokenRe, []string{label}, nil, getSharedVault(), false)
	out := string(outb)
	if out != "<div>hello</div>" {
		t.Fatalf("non-token content should pass through unchanged, got %q", out)
	}
}

func TestStreamAllowlistCachedPerStream(t *testing.T) {
	streamCarry.reset("k1")
	streamCarry.reset("k2")

	calls := 0
	build := func() map[string]struct{} {
		calls++
		return map[string]struct{}{"<REDACTED_1a2b3c4d5e6f7a8b>": {}}
	}

	// Repeated chunks of the same stream must reuse the cached allowlist.
	streamCarry.allowlist("k1", build)
	streamCarry.allowlist("k1", build)
	streamCarry.allowlist("k1", build)
	if calls != 1 {
		t.Fatalf("allowlist built %d times for one stream, want 1", calls)
	}

	// A different stream computes its own allowlist.
	streamCarry.allowlist("k2", build)
	if calls != 2 {
		t.Fatalf("allowlist built %d times across two streams, want 2", calls)
	}

	// Resetting the stream discards the cache; the next use rebuilds.
	streamCarry.reset("k1")
	streamCarry.allowlist("k1", build)
	if calls != 3 {
		t.Fatalf("allowlist built %d times after reset, want 3", calls)
	}
}

func TestCollectTokensRequiresVaultMappingAndIsBounded(t *testing.T) {
	tokenRe := restoreTokenPattern()
	v := newVault(streamAllowlistMaxTokens+10, time.Hour)
	var request strings.Builder
	request.WriteString(`<FORGED_0000000000000000>`)
	for i := 0; i < streamAllowlistMaxTokens+1; i++ {
		original := "secret-" + itoa(i)
		token := makeToken("L"+itoa(i), original)
		v.Put(token, original)
		request.WriteString(token)
	}

	allowed := collectTokens([]byte(request.String()), tokenRe, v)
	if _, ok := allowed[`<FORGED_0000000000000000>`]; ok {
		t.Fatal("forged token without a vault mapping entered the allowlist")
	}
	if len(allowed) != streamAllowlistMaxTokens {
		t.Fatalf("allowlist size = %d, want bounded size %d", len(allowed), streamAllowlistMaxTokens)
	}
	if labels := tokenLabels(allowed); len(labels) > streamAllowlistMaxTokens {
		t.Fatalf("token label count = %d, exceeds bound %d", len(labels), streamAllowlistMaxTokens)
	}
	for token := range allowed {
		if _, ok := v.Get(token); !ok {
			t.Fatalf("allowlist contains token without a vault mapping: %q", token)
		}
	}
}

func TestCollectTokensFindsJSONEscapedMappedTokens(t *testing.T) {
	tokenRe := restoreTokenPattern()
	v := newVault(10, time.Hour)
	token := makeToken("REDACTED", "secret")
	v.Put(token, "secret")
	request, err := json.Marshal(map[string]any{"value": token})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	escaped := strings.ReplaceAll(strings.ReplaceAll(string(request), "<", `\u003c`), ">", `\u003e`)
	allowed := collectTokens([]byte(escaped), tokenRe, v)
	if _, ok := allowed[token]; !ok {
		t.Fatalf("JSON-escaped mapped token missing from allowlist: request=%q allowed=%v", escaped, allowed)
	}
}

func TestResetStreamCarry(t *testing.T) {
	label, tokenRe := detokTestSetup()
	req := []byte(`{"model":"z"}`)
	key := streamKey(req)

	// Leave a remnant behind.
	partial := []byte("<REDACTED_1a2b")
	detokenizeStreamChunk(key, partial, tokenRe, []string{label}, nil, getSharedVault(), false)
	if !streamCarry.has(key) {
		t.Fatalf("expected a carried remnant")
	}
	resetStreamCarry(req)
	if streamCarry.has(key) {
		t.Fatalf("resetStreamCarry did not clear the remnant")
	}
}

func TestStreamStoreCapacityEvictsLeastRecentlyUsed(t *testing.T) {
	store := newStreamStore()
	for i := 0; i < streamCarryMaxEntries; i++ {
		key := "key-" + itoa(i)
		store.allowlist(key, func() map[string]struct{} { return map[string]struct{}{} })
	}
	store.allowlist("key-0", func() map[string]struct{} { return nil })
	store.allowlist("overflow", func() map[string]struct{} { return map[string]struct{}{} })
	if !store.has("key-0") {
		t.Fatal("recently touched entry was evicted")
	}
	if store.has("key-1") {
		t.Fatal("least recently used entry was not evicted")
	}
}

func TestStreamStoreGlobalByteBudgetEvictsLeastRecentlyUsed(t *testing.T) {
	store := newStreamStoreWithLimits(time.Minute, 12)
	if !store.setCarry("old", []byte("12345678")) {
		t.Fatal("first carry was unexpectedly rejected")
	}
	if !store.setCarry("new", []byte("abcdefgh")) {
		t.Fatal("second carry was unexpectedly rejected")
	}
	if store.has("old") {
		t.Fatal("least recently used carry was not evicted for global byte budget")
	}
	if !store.has("new") {
		t.Fatal("new carry was evicted instead of old carry")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.totalBytes > store.maxBytes {
		t.Fatalf("stream state bytes = %d, exceeds budget %d", store.totalBytes, store.maxBytes)
	}
}

func TestStreamStoreByteAccountingIncludesContentChannelNames(t *testing.T) {
	store := newStreamStore()
	key := "stream"
	channel := "openai:choice:0"
	pending := "<REDACTED_1a2b"

	store.mu.Lock()
	entry := store.getOrCreateLocked(key, time.Now())
	entry.content = map[string]string{channel: pending}
	store.resizeEntryLocked(entry)
	entryBytes := entry.bytes
	totalBytes := store.totalBytes
	store.mu.Unlock()

	want := len(key) + len(channel) + len(pending)
	if entryBytes != want || totalBytes != want {
		t.Fatalf("content state bytes: entry=%d total=%d, want %d including channel name", entryBytes, totalBytes, want)
	}
}

func TestStreamStoreCleanupRemovesIdleState(t *testing.T) {
	store := newStreamStoreWithLimits(20*time.Millisecond, streamStoreMaxBytes)
	store.startCleanup()
	defer store.stopCleanup()
	if !store.setCarry("idle", []byte("held")) {
		t.Fatal("carry was unexpectedly rejected")
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		_, exists := store.entries["idle"]
		store.mu.Unlock()
		if !exists {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("idle stream state was not proactively removed")
}

func TestStreamStoreExpiresAbandonedActiveState(t *testing.T) {
	store := newStreamStoreWithLimits(time.Minute, streamStoreMaxBytes)
	store.begin("active")
	store.allowlist("active", func() map[string]struct{} {
		return map[string]struct{}{"<REDACTED_0123456789abcdef>": {}}
	})
	store.mu.Lock()
	now := time.Now()
	store.entries["active"].touchedAt = now.Add(-2 * time.Minute)
	store.purgeLocked(now)
	store.mu.Unlock()
	if store.has("active") {
		t.Fatal("request with no completion notification survived idle TTL cleanup")
	}
	if _, initialized := store.activeAllowlist("active"); initialized {
		t.Fatal("expired request retained an initialized allowlist")
	}
}

func TestStreamStoreCompletionMarkerRetainsNoPayloadAndExpires(t *testing.T) {
	store := newStreamStoreWithLimits(time.Minute, streamStoreMaxBytes)
	store.begin("completed")
	store.allowlist("completed", func() map[string]struct{} {
		return map[string]struct{}{"<REDACTED_0123456789abcdef>": {}}
	})
	store.setCarry("completed", []byte("withheld"))
	store.end("completed")
	if store.has("completed") || store.begin("completed") {
		t.Fatal("completed request retained live state or accepted late initialization")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entry := store.entries["completed"]
	if entry == nil || !entry.completed || entry.active || entry.hasAllow || entry.allowed != nil || entry.carry != nil || entry.content != nil || entry.arguments != nil || entry.argumentOverflow {
		t.Fatalf("completion retained payload state: %+v", entry)
	}
	if store.totalBytes != len("completed") {
		t.Fatalf("completion retained %d bytes, want only the request ID", store.totalBytes)
	}
	now := time.Now()
	entry.touchedAt = now.Add(-2 * time.Minute)
	store.purgeLocked(now)
	if len(store.entries) != 0 || store.totalBytes != 0 {
		t.Fatal("completion marker did not expire")
	}
}

func TestStreamStoreCompletionMarkersStayBounded(t *testing.T) {
	for _, budget := range []int{128, streamStoreMaxBytes} {
		store := newStreamStoreWithLimits(time.Minute, budget)
		for i := 0; i < streamCarryMaxEntries+10; i++ {
			store.end("completed-" + itoa(i))
		}
		if len(store.entries) > streamCarryMaxEntries || store.totalBytes > budget {
			t.Fatalf("unbounded completion markers: entries=%d bytes=%d budget=%d", len(store.entries), store.totalBytes, budget)
		}
	}
}

func TestStreamStoreAllowlistBuildPreservesActiveStateAfterHardCapEviction(t *testing.T) {
	store := newStreamStore()
	store.begin("active")
	buildStarted := make(chan struct{})
	allowBuild := make(chan struct{})
	buildDone := make(chan struct{})
	go func() {
		store.allowlist("active", func() map[string]struct{} {
			close(buildStarted)
			<-allowBuild
			return map[string]struct{}{"<REDACTED_0123456789abcdef>": {}}
		})
		close(buildDone)
	}()
	<-buildStarted

	// Fill the hard entry cap with newer active streams. With no inactive
	// candidate available, the original active entry is the LRU eviction.
	for i := 0; i < streamCarryMaxEntries; i++ {
		store.begin("replacement-" + itoa(i))
	}
	close(allowBuild)
	<-buildDone

	store.mu.Lock()
	entry := store.entries["active"]
	active := entry != nil && entry.active
	store.mu.Unlock()
	if !active {
		t.Fatal("allowlist build recreated live stream state as inactive")
	}
}

func TestPluginShutdownClearsStreamState(t *testing.T) {
	callRegister(t, pluginabi.MethodPluginRegister, "")
	streamCarry.clear()
	if !streamCarry.setCarry("shutdown", []byte("held")) {
		t.Fatal("carry was unexpectedly rejected")
	}
	pluginShutdown()
	streamCarry.mu.Lock()
	remaining := len(streamCarry.entries)
	streamCarry.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("plugin shutdown retained %d stream entries", remaining)
	}
	callRegister(t, pluginabi.MethodPluginRegister, "")
}

func BenchmarkStreamStoreAllowlistEmpty(b *testing.B) {
	store := newStreamStore()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.allowlist("active", func() map[string]struct{} { return map[string]struct{}{} })
	}
}

func BenchmarkStreamStoreAllowlistFull(b *testing.B) {
	store := newStreamStore()
	for i := 0; i < streamCarryMaxEntries; i++ {
		key := "key-" + itoa(i)
		store.allowlist(key, func() map[string]struct{} { return map[string]struct{}{} })
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.allowlist("key-0", func() map[string]struct{} { return map[string]struct{}{} })
	}
}
