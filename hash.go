package crypto_utils

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
)

func MD5hash(args ...[]byte) []byte {
	digester := md5.New()
	for _, msgBytes := range args {
		digester.Write(msgBytes)
	}
	return digester.Sum(nil)
}

func SHA256hash(args ...[]byte) []byte {
	digester := sha256.New()
	for _, msgBytes := range args {
		digester.Write(msgBytes)
	}
	return digester.Sum(nil)
}

func SHA1hash(args ...[]byte) []byte {
	digester := sha1.New()
	for _, msgBytes := range args {
		digester.Write(msgBytes)
	}
	return digester.Sum(nil)
}

func InterfaceHash(digester hash.Hash, args ...[]byte) []byte {
	digester.Reset()
	for _, msgBytes := range args {
		digester.Write(msgBytes)
	}
	return digester.Sum(nil)
}
