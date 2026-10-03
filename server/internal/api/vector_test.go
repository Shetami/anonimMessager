package api

import "testing"

const accountIDVector = "s2qb422dlmi2wm2zzg5yptqcendg6hpe"

// Shared with ios/Packages/CalcCore (EnvelopeTests.accountIDMatchesServer):
// both sides must derive the same mailbox ID from an identity key.
func TestAccountIDVector(t *testing.T) {
	ik := append([]byte{0x05}, make([]byte, 32)...)
	got := AccountID(ik)
	if got != accountIDVector {
		t.Fatalf("got %s", got)
	}
}
