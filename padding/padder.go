package padding

import "strings"

type Padding interface {
	// Pad Pads data
	Pad([]byte, int) ([]byte, error)
	// Trim un-pads data
	Trim([]byte, int) ([]byte, error)
	// Name gives us the name of padding algo
	Name() string
}

var SupportedPaddings = map[string]Padding{
	strings.ToLower(defaultNoPadding.Name()):    defaultNoPadding,
	strings.ToLower(defaultPKCS5Padding.Name()): defaultPKCS5Padding,
	strings.ToLower(defaultPKCS7Padding.Name()): defaultPKCS7Padding,
}

type NoPadding struct{}

var defaultNoPadding = &NoPadding{}

func (p *NoPadding) Pad(data []byte, blockSize int) ([]byte, error) {
	return data, nil
}

func (p *NoPadding) Trim(data []byte, blockSize int) ([]byte, error) {
	return data, nil
}

func (p *NoPadding) Name() string {
	return "NONE"
}
