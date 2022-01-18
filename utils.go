package crypto_utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

type PaddingFunc func(data []byte, blockSize int) []byte
type UnPaddingFunc func(data []byte) []byte

//aes encryption, filling the 16 bits of the key key, 24, 32 respectively corresponding to AES-128, AES-192, or AES-256.
func AesCBCEncrypt(padding PaddingFunc, rawData, key, iv []byte) ([]byte, error) {
	var (
		block      cipher.Block
		cipherText []byte
		err        error
	)

	block, err = aes.NewCipher(key)
	if err == nil {
		//fill the original
		blockSize := block.BlockSize()
		rawData = padding(rawData, blockSize)
		// Initial vector IV must be unique, but does not need to be kept secret
		cipherText = make([]byte, blockSize+len(rawData))
		//block size 16

		//block size and initial vector size must be the same
		mode := cipher.NewCBCEncrypter(block, iv)
		///mode.CryptBlocks(cipherText[blockSize:],rawData)
		mode.CryptBlocks(cipherText, rawData)
	}

	return cipherText, err
}

func AesCTREncrypt(padding PaddingFunc, rawData, key, iv []byte) ([]byte, error) {
	var (
		block      cipher.Block
		cipherText []byte
		err        error
	)

	block, err = aes.NewCipher(key)
	if err == nil {
		blockSize := block.BlockSize()
		rawData = padding(rawData, blockSize)

		cipherText = make([]byte, len(rawData))
		//block size and initial vector size must be the same
		mode := cipher.NewCTR(block, iv)
		///mode.CryptBlocks(cipherText[blockSize:],rawData)
		mode.XORKeyStream(cipherText, rawData)
	}

	return cipherText, err
}

func AesCBCDecrypt(unPadder UnPaddingFunc, encryptData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(encryptData) < blockSize {
		return nil, ErrTextBlockSizeTooSmall
	}
	// iv := encryptData[:blockSize]
	encryptData = encryptData[blockSize:]

	// CBC mode always works in whole blocks.
	if len(encryptData)%blockSize != 0 {
		return nil, ErrTextBlockSizeNotMultiple
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(encryptData, encryptData)
	// Unfill
	encryptData = unPadder(encryptData)
	return encryptData, nil
}

func AesCTRDecrypt(unPadder UnPaddingFunc, encryptData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(encryptData) < blockSize {
		return nil, ErrTextBlockSizeTooSmall
	}
	// iv := encryptData[:blockSize]
	encryptData = encryptData[blockSize:]

	if len(encryptData)%blockSize != 0 {
		return nil, ErrTextBlockSizeNotMultiple
	}

	mode := cipher.NewCTR(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.XORKeyStream(encryptData, encryptData)
	// Unfill
	encryptData = unPadder(encryptData)
	return encryptData, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// Use PKCS7 to fill, IOS is also 7
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func NoPadding(cipherText []byte, blockSize int) []byte {
	return cipherText
}

func PKCS7UnPadding(origData []byte) []byte {
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
