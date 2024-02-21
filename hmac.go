package crypto_utils

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"github.com/OneOfOne/xxhash"
	"hash"
)

func HMACofMD5(key []byte, args ...[]byte) []byte {
	digester := hmac.New(md5.New, key)
	for _, msgBytes := range args {
		digester.Write(msgBytes)
	}
	return digester.Sum(nil)
}

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

func HMACofInterfaceHash(algo hash.Hash, key []byte, args ...[]byte) []byte {
	algo.Reset()
	digester := hmac.New(func() hash.Hash {
		return algo
	}, key)
	for _, msgBytes := range args {
		digester.Write(msgBytes)
	}
	return digester.Sum(nil)
}
