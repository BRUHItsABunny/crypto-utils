package ecdh

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

// ECDH utils

type KeyPair struct {
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
}

type auxKeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func (kp *KeyPair) MarshalJSON() ([]byte, error) {
	var pub, pri [32]byte
	err := cryptoToByteArray(&pri, kp.PrivateKey)
	if err != nil {
		return nil, err
	}
	err = cryptoToByteArray(&pub, kp.PublicKey)
	if err != nil {
		return nil, err
	}

	return json.Marshal(&auxKeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(pri[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pub[:]),
	})
}

func (kp *KeyPair) UnmarshalJSON(data []byte) error {
	var pub, pri [32]byte
	aux := new(auxKeyPair)
	err := json.Unmarshal(data, aux)
	if err == nil {
		_, err = base64.StdEncoding.Decode(pub[:], []byte(aux.PublicKey))
		if err != nil {
			return err
		}
		_, err = base64.StdEncoding.Decode(pri[:], []byte(aux.PrivateKey))
		if err != nil {
			return err
		}
		kp.PrivateKey = pri
		kp.PublicKey = pub
	}
	return err
}

type ECDH interface {
	// Crypto
	GenerateKeyPair(randSrc io.Reader, doPrivateMagic bool) (*KeyPair, error)
	GeneratePublicKey(priKey crypto.PrivateKey) (crypto.PublicKey, error)
	CalculateSharedKey(priKey crypto.PrivateKey, pubKey crypto.PublicKey) ([]byte, error)
	// Identification
	GetCurveBitSize() int
	GetCurveName() string
}

var ErrConvertUnable = errors.New("unable to convert key to byte array")

func cryptoToByteArray(dst *[32]byte, src interface{}) error {
	var err error

	switch typedSrc := src.(type) {
	case [32]byte:
		copy(dst[:], typedSrc[:])
	case *[32]byte:
		copy(dst[:], typedSrc[:])
	case []byte:
		if len(typedSrc) == 32 {
			copy(dst[:], typedSrc)
		}
	case *[]byte:
		if len(*typedSrc) == 32 {
			copy(dst[:], *typedSrc)
		}
	default:
		err = ErrConvertUnable
	}

	return err
}
