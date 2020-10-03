package doubleclick

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"hash"
)

const (
	initVectorOffset = 0
	initVectorLen    = 16
	cipherOffset     = 16
	integritySignLen = 4

	bufPadOffset     = 0
	bufPadLen        = 20
	bufPayloadOffset = 20
	bufSignLen       = 20 // integrity signature needs only 4 bytes buffer, but hmac makes 20-bytes array by default

	hextable = "0123456789abcdef"

	uuidDashPosTimeLow      = 4
	uuidDashPosTimeMid      = 6
	uuidDashPosTimeHiAndVer = 8
	uuidDashPosClockSeq     = 10
)

type DoubleClick struct {
	hmacE, hmacI hash.Hash

	buf, encryptionKey, integrityKey []byte
}

var (
	ErrSignCheckFail = errors.New("signature check failed")
)

func (d *DoubleClick) SetKeys(encryptionKey, integrityKey []byte) {
	d.encryptionKey, d.integrityKey = encryptionKey, integrityKey
}

func (d *DoubleClick) decrypt(dst, cipher []byte, payloadLen int) ([]byte, error) {
	initVector := cipher[initVectorOffset:initVectorLen]
	cipherText := cipher[cipherOffset : cipherOffset+payloadLen]
	integritySignOffset := cipherOffset + payloadLen
	integritySign := cipher[integritySignOffset : integritySignOffset+integritySignLen]

	// Prepare buffer.
	bufLen := bufPadLen + payloadLen + bufSignLen
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
	payload := d.buf[bufPayloadOffset : bufPayloadOffset+payloadLen]
	for i := 0; i < payloadLen; i++ {
		payload[i] = cipherText[i] ^ pad[i]
	}

	// Init encryption hmac.
	if d.hmacI == nil {
		d.hmacI = hmac.New(sha1.New, d.integrityKey)
	}
	// Compute signature.
	bufSignOffset := bufPayloadOffset + payloadLen
	computedSign := d.buf[bufSignOffset : bufSignOffset+bufSignLen]
	d.hmacI.Reset()
	d.hmacI.Write(payload)
	d.hmacI.Write(initVector)
	computedSign = d.hmacI.Sum(computedSign[:0])[:integritySignLen]
	if !hmac.Equal(computedSign, integritySign) {
		return dst, ErrSignCheckFail
	}

	dst = append(dst[:0], payload...)
	return dst, nil
}
