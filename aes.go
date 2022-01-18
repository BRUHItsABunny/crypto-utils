package crypto_utils

import (
	"crypto/aes"
	"crypto/cipher"
)

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

func AesGCMEncrypt(padding PaddingFunc, rawData, key, iv, aad []byte) ([]byte, error) {
	var (
		block      cipher.Block
		mode       cipher.AEAD
		cipherText []byte
		err        error
	)

	block, err = aes.NewCipher(key)
	if err == nil {
		blockSize := block.BlockSize()
		rawData = padding(rawData, blockSize)

		cipherText = make([]byte, len(rawData))
		mode, err = cipher.NewGCM(block)
		if err == nil {
			cipherText = mode.Seal(nil, iv, rawData, aad)
		}
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

func AesGCMDecrypt(unPadder UnPaddingFunc, cipherText, key, iv, aad []byte) ([]byte, error) {
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
			cipherText = cipherText[blockSize:]
			if len(cipherText)%blockSize != 0 {
				err = ErrTextBlockSizeNotMultiple
			}
			if err == nil {
				mode, err = cipher.NewGCM(block)

				if err == nil {
					decipherText, err = mode.Open(nil, iv, cipherText, aad)
					if err == nil {
						decipherText = unPadder(decipherText)
					}
				}
			}
		}
	}
	return decipherText, err
}
