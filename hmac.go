package crypto_utils

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"github.com/OneOfOne/xxhash"
)

func HMACofSHA1(key []byte, args ...[]byte) []byte {
	digester := hmac.New(sha1.New, key)
	for _, msgBytes := range args {
		digester.Write(msgBytes)
	}
	return digester.Sum(nil)
}

func HMACofSHA256(key []byte, args ...[]byte) []byte {
	digester := hmac.New(sha256.New, key)
	for _, msgBytes := range args {
		digester.Write(msgBytes)
	}
	return digester.Sum(nil)
}

func HMACofXXHash(key []byte, args ...[]byte) []byte {
	digester := hmac.New(xxhash.NewHash32, key) //Using 64bit or 32bit?
	for _, msgBytes := range args {
		digester.Write(msgBytes)
	}
	return digester.Sum(nil)
}
