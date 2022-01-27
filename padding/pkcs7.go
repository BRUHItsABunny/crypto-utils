package padding

import "bytes"

type PKCS7Padding struct{}

func (p *PKCS7Padding) Pad(data []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...), nil
}

func (p *PKCS7Padding) Trim(data []byte, blockSize int) ([]byte, error) {
	padding := data[len(data)-1]
	return data[:len(data)-int(padding)], nil
}

func (p *PKCS7Padding) Name() string {
	return "PKCS7"
}
