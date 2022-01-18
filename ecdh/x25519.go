package ecdh

import (
	"crypto"
	"crypto/rand"
	"golang.org/x/crypto/curve25519"
	"io"
)

type Curve25519 struct{}

func (c Curve25519) CalculateSharedKey(priKey crypto.PrivateKey, pubKey crypto.PublicKey) ([]byte, error) {
	var (
		pri, pub [32]byte
		err      error
	)

	err = cryptoToByteArray(&pri, priKey)
	if err != nil {
		return nil, err
	}
	err = cryptoToByteArray(&pub, pubKey)
	if err != nil {
		return nil, err
	}

	// curve25519.ScalarMult is deprecated
	return curve25519.X25519(pri[:], pub[:])
}

func (c Curve25519) GenerateKeyPair(randSrc io.Reader, doPrivateMagic bool) (*KeyPair, error) {
	if randSrc == nil {
		randSrc = rand.Reader
	}

	var (
		pri    [32]byte
		pubKey crypto.PublicKey
	)
	_, err := io.ReadFull(randSrc, pri[:])
	if err != nil {
		return nil, err
	}

	if doPrivateMagic {
		// SRC: https://cr.yp.to/ecdh.html
		pri[0] &= 248
		pri[31] &= 127
		pri[31] |= 64
	}

	pubKey, err = c.GeneratePublicKey(pri)
	if err == nil {
		return &KeyPair{
			PrivateKey: pri,
			PublicKey:  pubKey,
		}, nil
	}

	return nil, err
}

func (c Curve25519) GeneratePublicKey(priKey crypto.PrivateKey) (crypto.PublicKey, error) {
	var pri, pub [32]byte

	err := cryptoToByteArray(&pri, priKey)
	if err == nil {
		curve25519.ScalarBaseMult(&pub, &pri)
	}
	return pub, err
}

func (c Curve25519) GetCurveBitSize() int {
	return 255
}

func (c Curve25519) GetCurveName() string {
	return "Curve25519"
}

func NewCurve25519() ECDH {
	return &Curve25519{}
}
