package store

import "encoding/hex"

func encodeID(k []byte) string { return hex.EncodeToString(k) }

func decodeID(s string) ([]byte, bool) {
	k, err := hex.DecodeString(s)
	if err != nil || len(k) != 16 {
		return nil, false
	}
	return k, true
}
