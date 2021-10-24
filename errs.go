package crypto_utils

import "errors"

var (
	ErrTextBlockSizeTooSmall = errors.New("cipherText is too small")
	ErrTextBlockSizeNotMultiple = errors.New("ciphertext is not a multiple of the block size")
)
