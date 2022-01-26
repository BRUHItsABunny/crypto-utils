package crypto_utils

import (
	"bytes"
	"fmt"
)

type PaddingFunc func(data []byte, blockSize int) []byte
type UnPaddingFunc func(data []byte) []byte

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func NoPadding(cipherText []byte, blockSize int) []byte {
	return cipherText
}

func PKCS7UnPadding(origData []byte) []byte {
	fmt.Println(origData)
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func PKCS5UnPadding(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func NoUnPadding(data []byte) []byte {
	return data
}
