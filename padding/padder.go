package padding

type Padding interface {
	// Pad Pads data
	Pad([]byte, int) ([]byte, error)
	// Trim un-pads data
	Trim([]byte, int) ([]byte, error)
	// Name gives us the name of padding algo
	Name() string
}

var SupportedPaddings = map[string]Padding{
	"none":  &NoPadding{},
	"pkcs5": &PKCS5Padding{},
	"pkcs7": &PKCS7Padding{},
}

type NoPadding struct{}

func (p *NoPadding) Pad(data []byte, blockSize int) ([]byte, error) {
	return data, nil
}

func (p *NoPadding) Trim(data []byte, blockSize int) ([]byte, error) {
	return data, nil
}

func (p *NoPadding) Name() string {
	return "NONE"
}
