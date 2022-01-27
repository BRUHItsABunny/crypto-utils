package padding

import "bytes"

type PKCS5Padding struct{}

var defaultPKCS5Padding = &PKCS5Padding{}

func (p *PKCS5Padding) Pad(data []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...), nil
}

func (p *PKCS5Padding) Trim(data []byte, blockSize int) ([]byte, error) {
	padding := data[len(data)-1]
	return data[:len(data)-int(padding)], nil
}

func (p *PKCS5Padding) Name() string {
	return "PKCS5"
}
