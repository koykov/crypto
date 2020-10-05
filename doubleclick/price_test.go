package doubleclick

import (
	"bytes"
	"testing"
)

var (
	encryptedPrice = []byte{
		0x38, 0x6e, 0x3a, 0xc0, 0x00, 0x0c, 0x0a, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef, 0xe9, 0x8d, 0xcb, 0x45, 0x53, 0x28, 0xf6, 0xc1, 0xde, 0x8e, 0x42, 0x31,
	}
	decryptedPrice = 1.2
)

func TestDecryptPrice(t *testing.T) {
	d := New(TypePrice, encryptionKey, integrityKey)
	var (
		dst []byte
		err error
	)
	dst, err = d.DecryptPrice(dst, encryptedPrice)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(dst, decryptedIDFA) {
		t.Error("decrypt price failed")
	}
}
