package crypto_utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"github.com/OneOfOne/xxhash"
	"golang.org/x/crypto/curve25519"
)

type KeyData struct {
	PrivateKey []byte `json:"privateKey"`
	PublicKey  []byte `json:"publicKey"`
	Nonce      []byte `json:"nonce"`
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
func AesCBCEncrypt(rawData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	//fill the original
	blockSize := block.BlockSize()
	rawData = PKCS7Padding(rawData, blockSize)
	// Initial vector IV must be unique, but does not need to be kept secret
	cipherText := make([]byte, blockSize+len(rawData))
	//block size 16
	//block size and initial vector size must be the same
	mode := cipher.NewCBCEncrypter(block, iv)
	///mode.CryptBlocks(cipherText[blockSize:],rawData)
	mode.CryptBlocks(cipherText, rawData)

	return cipherText, nil
}

func AesCTREncrypt(rawData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	cipherText := make([]byte, len(rawData))
	//block size and initial vector size must be the same
	mode := cipher.NewCTR(block, iv)
	///mode.CryptBlocks(cipherText[blockSize:],rawData)
	mode.XORKeyStream(cipherText, rawData)

	return cipherText, nil
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

func AesCBCDecrypt(encryptData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	blockSize := block.BlockSize()

	if len(encryptData) < blockSize {
		panic("ciphertext too short")
	}
	// iv := encryptData[:blockSize]
	encryptData = encryptData[blockSize:]

	// CBC mode always works in whole blocks.
	if len(encryptData)%blockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(encryptData, encryptData)
	// Unfill
	encryptData = PKCS7UnPadding(encryptData)
	return encryptData, nil
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
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

	return PKCS5Trimming(decrypted)
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

func pkcs7pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 0 || blockSize > 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	} else {
		padLen := blockSize - len(data)%blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
