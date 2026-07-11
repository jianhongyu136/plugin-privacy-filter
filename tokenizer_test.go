package main

import (
	"regexp"
	"testing"
	"time"
)

func TestMakeTokenDeterministic(t *testing.T) {
	a := makeToken("REDACTED", "sk-secret-value-123456")
	b := makeToken("REDACTED", "sk-secret-value-123456")
	if a != b {
		t.Fatalf("expected deterministic token, got %q and %q", a, b)
	}
}

func TestMakeTokenDistinct(t *testing.T) {
	a := makeToken("REDACTED", "secret-one")
	b := makeToken("REDACTED", "secret-two")
	if a == b {
		t.Fatalf("expected distinct tokens for distinct inputs, both were %q", a)
	}
}

func TestMakeTokenFormat(t *testing.T) {
	tok := makeToken("REDACTED", "anything")
	re := regexp.MustCompile(`^<REDACTED_[0-9a-f]{16}>$`)
	if !re.MatchString(tok) {
		t.Fatalf("token %q does not match <REDACTED_<16 hex>> format", tok)
	}
}

func TestTokenPatternMatchesMakeToken(t *testing.T) {
	tok := makeToken("REDACTED", "x")
	re := tokenPattern("REDACTED")
	if !re.MatchString(tok) {
		t.Fatalf("tokenPattern did not match its own token %q", tok)
	}
}

func TestNewRedactFuncWritesVault(t *testing.T) {
	setSharedVault(newVault(10, time.Hour))
	redact := newRedactFunc("REDACTED", getSharedVault())
	original := "sk-abcdefghij0123456789"
	tok := redact(original)
	got, ok := getSharedVault().Get(tok)
	if !ok || got != original {
		t.Fatalf("vault did not store original for token %q: got=%q ok=%v", tok, got, ok)
	}
}
