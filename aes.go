package crypto_utils

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/BRUHItsABunny/crypto-utils/padding"
)

func AesECBEncrypt(padding padding.Padding, rawData, key []byte) ([]byte, error) {
	var (
		block      cipher.Block
		cipherText []byte
		err        error
	)

	block, err = aes.NewCipher(key)
	if err == nil {
		blockSize := block.BlockSize()
		rawData, err = padding.Pad(rawData, blockSize)
		if err == nil {

			result := make([]byte, len(rawData))
			temp := result
			for len(rawData) > 0 {
				block.Encrypt(temp, rawData[:blockSize])
				rawData = rawData[blockSize:]
				temp = temp[blockSize:]
			}
			cipherText = result
		}
	}

	return cipherText, err
}

func AesCBCEncrypt(padding padding.Padding, rawData, key, iv []byte) ([]byte, error) {
	var (
		block      cipher.Block
		cipherText []byte
		err        error
	)

	block, err = aes.NewCipher(key)
	if err == nil {
		//fill the original
		blockSize := block.BlockSize()
		rawData, err = padding.Pad(rawData, blockSize)
		if err == nil {
			cipherText = make([]byte, len(rawData))
			//block size and initial vector size must be the same
			mode := cipher.NewCBCEncrypter(block, iv)
			mode.CryptBlocks(cipherText, rawData)
		}
	}

	return cipherText, err
}

func AesCTREncrypt(padding padding.Padding, rawData, key, iv []byte) ([]byte, error) {
	var (
		block      cipher.Block
		cipherText []byte
		err        error
	)

	block, err = aes.NewCipher(key)
	if err == nil {
		blockSize := block.BlockSize()
		rawData, err = padding.Pad(rawData, blockSize)
		if err == nil {
			cipherText = make([]byte, len(rawData))
			//block size and initial vector size must be the same
			mode := cipher.NewCTR(block, iv)
			mode.XORKeyStream(cipherText, rawData)
		}
	}

	return cipherText, err
}

func AesGCMEncrypt(padding padding.Padding, rawData, key, iv, aad []byte) ([]byte, error) {
	var (
		block      cipher.Block
		mode       cipher.AEAD
		cipherText []byte
		err        error
	)

	block, err = aes.NewCipher(key)
	if err == nil {
		blockSize := block.BlockSize()
		rawData, err = padding.Pad(rawData, blockSize)
		if err == nil {
			cipherText = make([]byte, len(rawData))
			mode, err = cipher.NewGCM(block)
			if err == nil {
				cipherText = mode.Seal(nil, iv, rawData, aad)
			}
		}
	}

	return cipherText, err
}

func AesECBDecrypt(padding padding.Padding, encryptData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	result := make([]byte, len(encryptData))

	temp := result
	for len(encryptData) > 0 {
		block.Decrypt(temp, encryptData[:blockSize])
		encryptData = encryptData[blockSize:]
		temp = temp[blockSize:]
	}

	result, err = padding.Trim(result, blockSize)
	return result, err
}

func AesCBCDecrypt(padding padding.Padding, encryptData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(encryptData) < blockSize {
		return nil, ErrTextBlockSizeTooSmall
	}

	// CBC mode always works in whole blocks.
	if len(encryptData)%blockSize != 0 {
		return nil, ErrTextBlockSizeNotMultiple
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	data := make([]byte, len(encryptData))
	mode.CryptBlocks(data, encryptData)

	// Trim data
	data, err = padding.Trim(data, blockSize)
	return data, err
}

func AesCTRDecrypt(padding padding.Padding, encryptData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(encryptData) < blockSize {
		return nil, ErrTextBlockSizeTooSmall
	}

	if len(encryptData)%blockSize != 0 {
		return nil, ErrTextBlockSizeNotMultiple
	}

	mode := cipher.NewCTR(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.XORKeyStream(encryptData, encryptData)
	// Trim data
	encryptData, err = padding.Trim(encryptData, blockSize)
	return encryptData, err
}

func AesGCMDecrypt(padding padding.Padding, cipherText, key, iv, aad []byte) ([]byte, error) {
	var (
		block        cipher.Block
		mode         cipher.AEAD
		decipherText []byte
		err          error
	)

	block, err = aes.NewCipher(key)
	if err == nil {
		blockSize := block.BlockSize()
		if len(cipherText) < blockSize {
			err = ErrTextBlockSizeTooSmall
		}
		if err == nil {
			// cipherText = cipherText[blockSize:]
			// if len(cipherText)%blockSize != 0 {
			// 	err = ErrTextBlockSizeNotMultiple
			// }
			if err == nil {
				mode, err = cipher.NewGCM(block)

				if err == nil {
					decipherText, err = mode.Open(nil, iv, cipherText, aad)
					if err == nil {
						decipherText, err = padding.Trim(decipherText, blockSize)
					}
				}
			}
		}
	}
	return decipherText, err
}
