package crypto_utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/curve25519"
)

type PaddingFunc func(data []byte, blockSize int) []byte
type UnPaddingFunc func(data []byte) []byte

type KeyData struct {
	PrivateKey []byte `json:"privateKey"`
	PublicKey  []byte `json:"publicKey"`
	Nonce      []byte `json:"nonce"`
}

func GenerateCurve255519KeyData() (KeyData, error) {
	result := KeyData{}
	result.PrivateKey = make([]byte, 32)
	_, err := rand.Read(result.PrivateKey)

	if err == nil {
		var privateKeyByteArr [32]byte
		copy(privateKeyByteArr[:], result.PrivateKey)
		var publicKey [32]byte
		curve25519.ScalarBaseMult(&publicKey, &privateKeyByteArr)
		result.PublicKey = publicKey[:]

		result.Nonce = make([]byte, 16)
		_, err = rand.Read(result.Nonce)
	}

	return result, err
}

//aes encryption, filling the 16 bits of the key key, 24, 32 respectively corresponding to AES-128, AES-192, or AES-256.
func AesCBCEncrypt(padding PaddingFunc, rawData, key, iv []byte) ([]byte, error) {
	var (
		block cipher.Block
		cipherText []byte
		err error
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
		block cipher.Block
		cipherText []byte
		err error
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

func AESCBCPKCS7Encrypt(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key) //选择加密算法
	if err != nil {
		return nil, err
	}
	data = PKCS7Padding(data, block.BlockSize())
	if iv == nil {
		iv = key
	}
	blockModel := cipher.NewCBCEncrypter(block, iv[:block.BlockSize()])
	ciphertext := make([]byte, len(data))
	blockModel.CryptBlocks(ciphertext, data)
	return ciphertext, nil
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

	// CBC mode always works in whole blocks.
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

func AESEncrypt(data []byte, key []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	ecb := cipher.NewCBCEncrypter(block, iv)
	data, _ = pkcs7pad(data, block.BlockSize())
	crypted := make([]byte, len(data))
	ecb.CryptBlocks(crypted, data)

	return crypted
}

func AESDecrypt(crypt []byte, key []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	if len(crypt) == 0 {
		fmt.Println("plain content empty")
	}
	ecb := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(crypt))
	ecb.CryptBlocks(decrypted, crypt)

	return PKCS5UnPadding(decrypted)
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

func pkcs7pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 0 || blockSize > 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	} else {
		padLen := blockSize - len(data)%blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
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
