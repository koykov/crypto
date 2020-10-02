package double_click

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
)

const (
	msgLen              = 36
	initVectorOffset    = 0
	initVectorLen       = 16
	cipherOffset        = 16
	cipherLen           = 16
	integritySignOffset = 32
	integritySignLen    = 4

	bufPadOffset     = 0
	bufPadLen        = 20
	bufPayloadOffset = 20
	bufPayloadLen    = 16
	bufSignOffset    = 36
	bufSignLen       = 20 // integrity signature needs only 4 bytes buffer, but hmac makes 20-bytes array by default
	bufLen           = bufPadLen + bufPayloadLen + bufSignLen

	hextable = "0123456789abcdef"
)

type DoubleClick struct {
	hmacE, hmacI hash.Hash

	buf, encryptionKey, integrityKey []byte
}

var (
	ErrBadMsgLen     = errors.New(fmt.Sprintf("message length must be %d", msgLen))
	ErrSignCheckFail = errors.New("signature check failed")

	resetBuf = make([]byte, bufLen)
)

func New(encryptionKey, integrityKey []byte) *DoubleClick {
	d := &DoubleClick{}
	d.SetKeys(encryptionKey, integrityKey)
	return d
}

func (d *DoubleClick) SetKeys(encryptionKey, integrityKey []byte) {
	d.encryptionKey, d.integrityKey = encryptionKey, integrityKey
}

func (d *DoubleClick) Decrypt(encryptedID []byte) ([]byte, error) {
	var dst []byte
	return d.decrypt(dst, encryptedID, false)
}

func (d *DoubleClick) DecryptUUID(encryptedID []byte) ([]byte, error) {
	var dst []byte
	return d.decrypt(dst, encryptedID, true)
}

func (d *DoubleClick) AppendDecrypt(dst, encryptedID []byte) ([]byte, error) {
	return d.decrypt(dst, encryptedID, false)
}

func (d *DoubleClick) AppendDecryptUUID(dst, encryptedID []byte) ([]byte, error) {
	return d.decrypt(dst, encryptedID, true)
}

func (d *DoubleClick) decrypt(dst, encryptedID []byte, uuid bool) ([]byte, error) {
	if len(encryptedID) != msgLen {
		return dst, ErrBadMsgLen
	}

	initVector := encryptedID[initVectorOffset:initVectorLen]
	cipherText := encryptedID[cipherOffset : cipherOffset+cipherLen]
	integritySign := encryptedID[integritySignOffset : integritySignOffset+integritySignLen]

	// Prepare buffer.
	if len(d.buf) < bufLen {
		d.buf = append(d.buf, make([]byte, bufLen-len(d.buf))...)
	}

	// Init encryption hmac.
	if d.hmacE == nil {
		d.hmacE = hmac.New(sha1.New, d.encryptionKey)
	}
	// Compute pad.
	pad := d.buf[bufPadOffset:bufPadLen]
	d.hmacE.Reset()
	d.hmacE.Write(initVector)
	pad = d.hmacE.Sum(pad[:0])

	// Apply xor to reverse encryption.
	payload := d.buf[bufPayloadOffset : bufPayloadOffset+bufPayloadLen]
	for i := 0; i < cipherLen; i++ {
		payload[i] = cipherText[i] ^ pad[i]
	}

	// Init encryption hmac.
	if d.hmacI == nil {
		d.hmacI = hmac.New(sha1.New, d.integrityKey)
	}
	// Compute signature.
	computedSign := d.buf[bufSignOffset : bufSignOffset+bufSignLen]
	d.hmacI.Reset()
	d.hmacI.Write(payload)
	d.hmacI.Write(initVector)
	computedSign = d.hmacI.Sum(computedSign[:0])[:integritySignLen]
	if !hmac.Equal(computedSign, integritySign) {
		return dst, ErrSignCheckFail
	}

	if uuid {
		// Convert payload to uuid.
		for i := 0; i < bufPayloadLen; i++ {
			switch i {
			case 4, 6, 8, 10:
				dst = append(dst, '-')
			}
			dst = append(dst, hextable[payload[i]>>4])
			dst = append(dst, hextable[payload[i]&0x0f])
		}
	} else {
		// Return raw payload.
		dst = append(dst[:0], payload...)
	}

	return dst, nil
}

func (d *DoubleClick) Reset() {
	d.buf = append(d.buf[:0], resetBuf...)
}
