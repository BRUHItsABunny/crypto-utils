package ecdh

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

var (
	// This key pair is not valid as the public key does NOT belong to this private key
	// SRC: Java
	testJSON = []byte("{\"private_key\":\"wAycgPF0rjQC9IvR2hXWLN+O3ZG4chAlKj+ZE3ilI10=\",\"public_key\":\"WvnLAyQ5nqQFp6lfuGKc2U0vowyzcqHkJirnpN18ADI=\"}")
)

func TestKeyPair_JSON(t *testing.T) {
	parsed := new(KeyPair)
	err := json.Unmarshal(testJSON, parsed)
	if err != nil {
		t.Error(err)
	}

	jsonBytes, err := json.Marshal(parsed)
	if err != nil {
		t.Error(err)
	}
	if string(testJSON) != string(jsonBytes) {
		t.Error("Encoding was different\nExpected: " + string(testJSON) + "\nGot : " + string(jsonBytes))
	}
}

func TestCurve25519_CalculateSharedKey(t *testing.T) {
	parsed := new(KeyPair)
	err := json.Unmarshal(testJSON, parsed)
	if err != nil {
		t.Error(err)
	}

	enc := NewCurve25519()
	sharedKey, err := enc.CalculateSharedKey(parsed.PrivateKey, parsed.PublicKey)
	if err != nil {
		t.Error(err)
	}
	base64EncKey := base64.StdEncoding.EncodeToString(sharedKey)
	if base64EncKey != "FXy0ZiN+xXbO7crAEgHENvhuh8RG94k2yMHjj+qWwVo=" {
		t.Error("unexpected key, got: " + base64EncKey)
	}
}
