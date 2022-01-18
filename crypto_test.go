package crypto_utils

import (
	"encoding/base64"
	"fmt"
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

	encData, err := AesECBEncrypt(PKCS7Padding, data, key)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(encData))

	data2, err := AesECBDecrypt(PKCS7UnPadding, encData, key)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(data))
	fmt.Println(base64.StdEncoding.EncodeToString(data2))
}
