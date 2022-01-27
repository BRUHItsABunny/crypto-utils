package crypto_utils

import (
	"encoding/base64"
	"fmt"
	"github.com/BRUHItsABunny/crypto-utils/padding"
	"math/rand"
	"testing"
	"time"
)

func TestAesECBCrypto(t *testing.T) {
	// We want to be able to encrypt and get expected data and we want to decrypt and get expected data
	key := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	_, err := rand.Read(key)
	if err != nil {
		t.Error(err)
	}

	data := []byte("TestData")

	encData, err := AesECBEncrypt(padding.SupportedPaddings["pkcs7"], data, key)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(encData))

	data2, err := AesECBDecrypt(padding.SupportedPaddings["pkcs7"], encData, key)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(data))
	fmt.Println(base64.StdEncoding.EncodeToString(data2))
}

func TestAesCBCDecrypt(t *testing.T) {
	key, err := base64.StdEncoding.DecodeString("D3W+fwkwLpPjePQp+VPrRbQZsuQXlwrxMIJtmIssGig=")
	if err != nil {
		t.Error(err)
	}
	IV, err := base64.StdEncoding.DecodeString("raRw6/OKlPDgHRMwZQ2f9w==")
	if err != nil {
		t.Error(err)
	}
	data, err := base64.StdEncoding.DecodeString("S5hGFVN6PbGw+pxY7SZ7ko06Nc5ksSs4EKdcDQW3VgI=")
	if err != nil {
		t.Error(err)
	}
	expected := "{\"text\":\"this is v1\"}"

	result, err := AesCBCDecrypt(padding.SupportedPaddings["pkcs7"], data, key, IV)
	if err != nil {
		t.Error(err)
	}
	if string(result) != expected {
		fmt.Println(string(result))
		t.Error("result != expected")
	}
}
