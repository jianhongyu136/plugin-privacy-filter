package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// tokenHexLen is the fixed number of hex characters in a token's hash segment.
// A fixed length lets the streaming detokenizer know the exact byte count of a
// complete token, which is essential for detecting a token truncated at a chunk
// boundary.
const tokenHexLen = 16

// tokenKey is a per-process random secret used to key the token hash. It makes
// tokens unpredictable: an attacker cannot precompute or offline-brute-force the
// token for a guessed secret (e.g. a low-entropy password) without this key,
// which never leaves the process and is regenerated on every restart.
var tokenKey = mustRandomKey()

// mustRandomKey returns 32 bytes of cryptographically secure randomness. It
// panics only if the OS CSPRNG is unavailable, which is a fatal environment
// fault; the plugin cannot provide its security guarantee without it.
func mustRandomKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("privacy-filter: unable to read random token key: " + err.Error())
	}
	return k
}

// makeToken builds a deterministic (within this process), self-delimiting
// placeholder token for an original secret. Format: "<" + label + "_" + first 16
// hex chars of HMAC-SHA256(tokenKey, original) + ">". The same label+original
// yields the same token for the process lifetime, giving idempotency and dedup,
// while the keyed hash prevents offline reversal of the original value.
func makeToken(label, original string) string {
	mac := hmac.New(sha256.New, tokenKey)
	mac.Write([]byte(original))
	h := hex.EncodeToString(mac.Sum(nil))
	return "<" + label + "_" + h[:tokenHexLen] + ">"
}

// tokenPattern compiles a regexp that matches any token produced by makeToken
// for the given label. The label is regexp-quoted so labels with regexp
// metacharacters are matched literally.
func tokenPattern(label string) *regexp.Regexp {
	return regexp.MustCompile("<" + regexp.QuoteMeta(label) + "_[0-9a-f]{" + itoa(tokenHexLen) + "}>")
}

// restoreTokenPattern matches token candidates minted under any configured
// label. Restoration still requires request allowlisting and an exact vault hit.
func restoreTokenPattern() *regexp.Regexp {
	return regexp.MustCompile("<[^<>\\r\\n]+_[0-9a-f]{" + itoa(tokenHexLen) + "}>")
}

// existingTokenMatcher recognizes only token candidates that still have an
// exact mapping in the shared vault. Candidate shape alone is not proof that a
// value was emitted by this plugin; treating it as trusted would let a forged
// token-shaped string shield embedded secrets from request scanning.
type existingTokenMatcher struct {
	candidate *regexp.Regexp
	vault     *vault
}

func (m existingTokenMatcher) MatchString(value string) bool {
	return m.FindString(value) != ""
}

func (m existingTokenMatcher) FindString(value string) string {
	indices := m.FindAllStringIndex(value, 1)
	if len(indices) == 0 {
		return ""
	}
	return value[indices[0][0]:indices[0][1]]
}

func (m existingTokenMatcher) FindAllStringIndex(value string, limit int) [][]int {
	if m.candidate == nil || m.vault == nil || limit == 0 {
		return nil
	}
	known := make([][]int, 0)
	for offset := 0; offset < len(value); {
		pair := m.candidate.FindStringIndex(value[offset:])
		if pair == nil {
			break
		}
		pair[0] += offset
		pair[1] += offset
		if _, ok := m.vault.Get(value[pair[0]:pair[1]]); !ok {
			offset = pair[1]
			continue
		}
		known = append(known, pair)
		if limit > 0 && len(known) == limit {
			break
		}
		offset = pair[1]
	}
	return known
}

// newRedactFunc returns a redactFunc that tokenizes an original value and
// persists the token->original mapping in the given vault so the response side
// can later restore it. The vault write is best-effort: if v is nil the token is
// still returned (the request stays redacted). The vault is passed in (rather
// than read from the global) so a handler uses the same vault, label, and rules
// from one runtime snapshot, never a triple torn across a concurrent reconfigure.
func newRedactFunc(label string, v *vault) redactFunc {
	return func(original string) string {
		token := makeToken(label, original)
		if v != nil {
			v.Put(token, original)
		}
		return token
	}
}

// itoa converts a small non-negative int to its decimal string without pulling
// in strconv at call sites; tokenHexLen is the only caller.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
