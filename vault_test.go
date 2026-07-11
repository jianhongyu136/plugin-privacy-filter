package main

import (
	"testing"
	"time"
)

func TestVaultPutGet(t *testing.T) {
	v := newVault(10, time.Hour)
	v.Put("<REDACTED_aaa>", "secret-value")
	got, ok := v.Get("<REDACTED_aaa>")
	if !ok || got != "secret-value" {
		t.Fatalf("got (%q, %v), want (%q, true)", got, ok, "secret-value")
	}
	if _, ok := v.Get("<REDACTED_missing>"); ok {
		t.Fatalf("expected miss for unknown token")
	}
}

func TestVaultTTLExpiry(t *testing.T) {
	v := newVault(10, 20*time.Millisecond)
	v.Put("<REDACTED_bbb>", "secret")
	time.Sleep(40 * time.Millisecond)
	if _, ok := v.Get("<REDACTED_bbb>"); ok {
		t.Fatalf("expected token to be expired after TTL")
	}
}

func TestVaultLRUEviction(t *testing.T) {
	v := newVault(2, time.Hour)
	v.Put("<REDACTED_1>", "one")
	v.Put("<REDACTED_2>", "two")
	// Access token 1 so it becomes most-recently-used.
	if _, ok := v.Get("<REDACTED_1>"); !ok {
		t.Fatalf("token 1 should still be present")
	}
	// Inserting a third entry must evict the least-recently-used (token 2).
	v.Put("<REDACTED_3>", "three")
	if _, ok := v.Get("<REDACTED_2>"); ok {
		t.Fatalf("token 2 should have been evicted as LRU")
	}
	if _, ok := v.Get("<REDACTED_1>"); !ok {
		t.Fatalf("token 1 should survive eviction")
	}
	if _, ok := v.Get("<REDACTED_3>"); !ok {
		t.Fatalf("token 3 should be present")
	}
}

func TestVaultClear(t *testing.T) {
	v := newVault(10, time.Hour)
	v.Put("<REDACTED_ccc>", "secret")
	v.Clear()
	if v.Len() != 0 {
		t.Fatalf("expected empty vault after Clear, got len %d", v.Len())
	}
}

func TestVaultReinsertRefreshesExisting(t *testing.T) {
	v := newVault(10, time.Hour)
	v.Put("<REDACTED_dddd>", "secret")
	v.Put("<REDACTED_dddd>", "secret") // idempotent re-put must not grow the store
	if v.Len() != 1 {
		t.Fatalf("expected len 1 after duplicate Put, got %d", v.Len())
	}
}

func TestVaultCleanupRemovesIdleExpiredPlaintext(t *testing.T) {
	v := newVault(10, 20*time.Millisecond)
	v.startCleanup()
	defer v.stopCleanup()
	v.Put("<REDACTED_idle>", "idle-secret")

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		v.mu.Lock()
		remaining := len(v.items)
		v.mu.Unlock()
		if remaining == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("background cleanup did not remove expired idle plaintext")
}

func TestVaultReconfigureEnforcesNewCapacity(t *testing.T) {
	v := newVault(3, time.Hour)
	v.Put("one", "1")
	v.Put("two", "2")
	v.Put("three", "3")
	v.reconfigure(1, time.Minute)
	if got := v.Len(); got != 1 {
		t.Fatalf("reconfigured capacity left %d entries, want 1", got)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.ttl != time.Minute {
		t.Fatalf("ttl = %v, want %v", v.ttl, time.Minute)
	}
}
