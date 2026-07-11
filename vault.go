package main

import (
	"container/list"
	"sync"
	"time"
)

// vaultEntry is the value stored in the LRU list.
type vaultEntry struct {
	token     string
	original  string
	expiresAt time.Time
}

// vaultPurgeInterval throttles the full expired-entry sweep. A per-token expiry
// check on Get keeps reads correct at all times; the full sweep only reclaims
// never-accessed expired entries, so running it at most once per interval avoids
// an O(n) list walk on every Put while still bounding stale plaintext lifetime.
const vaultPurgeInterval = time.Second

// vault is a concurrency-safe, bounded token->plaintext map with TTL and LRU
// eviction. It holds plaintext secrets in memory only; nothing is persisted.
type vault struct {
	mu             sync.Mutex
	maxEntries     int
	ttl            time.Duration
	ll             *list.List               // front = most recently used
	items          map[string]*list.Element // token -> element in ll
	lastPurge      time.Time                // last time purgeExpiredLocked swept
	cleanupRunning bool
	cleanupStop    chan struct{}
	cleanupWake    chan struct{}
	cleanupDone    chan struct{}
}

func (v *vault) reconfigure(maxEntries int, ttl time.Duration) {
	if maxEntries < 1 {
		maxEntries = 1
	}
	v.mu.Lock()
	v.maxEntries = maxEntries
	v.ttl = ttl
	v.purgeExpiredLocked(time.Now())
	for v.ll.Len() > v.maxEntries {
		v.removeElement(v.ll.Back())
	}
	wake := v.cleanupWake
	running := v.cleanupRunning
	v.mu.Unlock()
	if running {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (v *vault) startCleanup() {
	v.mu.Lock()
	if v.cleanupRunning {
		v.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	v.cleanupRunning = true
	v.cleanupStop = stop
	v.cleanupWake = wake
	v.cleanupDone = done
	v.mu.Unlock()
	go v.cleanupLoop(stop, wake, done)
}

func (v *vault) stopCleanup() {
	v.mu.Lock()
	if !v.cleanupRunning {
		v.mu.Unlock()
		return
	}
	stop := v.cleanupStop
	done := v.cleanupDone
	v.cleanupRunning = false
	v.cleanupStop = nil
	v.cleanupWake = nil
	v.cleanupDone = nil
	close(stop)
	v.mu.Unlock()
	<-done
}

func (v *vault) cleanupLoop(stop <-chan struct{}, wake <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	for {
		v.mu.Lock()
		interval := v.ttl
		if interval <= 0 || interval > vaultPurgeInterval {
			interval = vaultPurgeInterval
		}
		if interval < 10*time.Millisecond {
			interval = 10 * time.Millisecond
		}
		v.mu.Unlock()

		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
			v.mu.Lock()
			v.purgeExpiredLocked(time.Now())
			v.mu.Unlock()
		case <-wake:
			if !timer.Stop() {
				<-timer.C
			}
		case <-stop:
			if !timer.Stop() {
				<-timer.C
			}
			return
		}
	}
}

// newVault creates a vault bounded to maxEntries with the given TTL.
func newVault(maxEntries int, ttl time.Duration) *vault {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &vault{
		maxEntries: maxEntries,
		ttl:        ttl,
		ll:         list.New(),
		items:      make(map[string]*list.Element),
	}
}

// Put stores or refreshes the mapping token->original and marks it most
// recently used, evicting the least recently used entry if over capacity.
func (v *vault) Put(token, original string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := time.Now()
	v.purgeExpiredThrottledLocked(now)
	exp := now.Add(v.ttl)
	if el, ok := v.items[token]; ok {
		en := el.Value.(*vaultEntry)
		en.original = original
		en.expiresAt = exp
		v.ll.MoveToFront(el)
		return
	}
	el := v.ll.PushFront(&vaultEntry{token: token, original: original, expiresAt: exp})
	v.items[token] = el
	for v.ll.Len() > v.maxEntries {
		v.removeElement(v.ll.Back())
	}
}

// Get returns the original for a token if present and not expired.
func (v *vault) Get(token string) (string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	el, ok := v.items[token]
	if !ok {
		return "", false
	}
	en := el.Value.(*vaultEntry)
	if time.Now().After(en.expiresAt) {
		v.removeElement(el)
		return "", false
	}
	v.ll.MoveToFront(el)
	return en.original, true
}

// Len returns the current number of unexpired stored entries.
func (v *vault) Len() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.purgeExpiredLocked(time.Now())
	return v.ll.Len()
}

// purgeExpiredLocked removes every entry whose TTL elapsed on or before now.
// Entries are kept in the list ordered by recency, not expiry, so it scans all
// of them. Caller must hold v.mu.
func (v *vault) purgeExpiredLocked(now time.Time) {
	for el := v.ll.Front(); el != nil; {
		next := el.Next()
		if now.After(el.Value.(*vaultEntry).expiresAt) {
			v.removeElement(el)
		}
		el = next
	}
	v.lastPurge = now
}

// purgeExpiredThrottledLocked runs a full sweep only if at least
// vaultPurgeInterval has elapsed since the last one, so a burst of Put calls
// does not trigger repeated O(n) list walks. Read correctness does not depend on
// it (Get checks each entry's expiry on access); it only bounds how long
// never-accessed expired plaintext can linger. Caller must hold v.mu.
func (v *vault) purgeExpiredThrottledLocked(now time.Time) {
	if now.Sub(v.lastPurge) < vaultPurgeInterval {
		return
	}
	v.purgeExpiredLocked(now)
}

// Clear removes all entries.
func (v *vault) Clear() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.ll.Init()
	v.items = make(map[string]*list.Element)
}

// removeElement deletes an element from both the list and the index.
// Caller must hold v.mu.
func (v *vault) removeElement(el *list.Element) {
	if el == nil {
		return
	}
	v.ll.Remove(el)
	delete(v.items, el.Value.(*vaultEntry).token)
}

// getSharedVault returns the vault from the current runtime snapshot, or nil if
// configuration has not been applied yet. Production request/response handlers
// should instead read a single activeSnapshot() and use its vault together with
// its label and rules, so the triple is never observed torn across a reconfigure.
func getSharedVault() *vault {
	if st := activeState.Load(); st != nil {
		return st.vault
	}
	return nil
}

// setSharedVault replaces only the vault of the current runtime snapshot,
// preserving the active rules and label. It exists for tests and internal setup;
// the normal path publishes a full snapshot via applyConfig.
func setSharedVault(v *vault) {
	ns := &runtimeState{vault: v}
	if prev := activeState.Load(); prev != nil {
		ns.rules = prev.rules
		ns.label = prev.label
		ns.tokenRe = prev.tokenRe
		ns.restoreTokenRe = prev.restoreTokenRe
	}
	if ns.restoreTokenRe == nil {
		ns.restoreTokenRe = restoreTokenPattern()
	}
	activeState.Store(ns)
}
