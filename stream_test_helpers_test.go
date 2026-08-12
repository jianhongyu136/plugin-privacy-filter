package main

import (
	"crypto/sha256"
	"encoding/hex"
)

// streamKey gives older tests a deterministic schema-v4 StreamID.
func streamKey(requestBody []byte) string {
	sum := sha256.Sum256(requestBody)
	return hex.EncodeToString(sum[:])
}

func resetStreamCarry(requestBody []byte) {
	streamCarry.reset(streamKey(requestBody))
}
