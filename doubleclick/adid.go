package doubleclick

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
)

const (
	adidMsgLen              = 36
	adidInitVectorOffset    = 0
	adidInitVectorLen       = 16
	adidCipherOffset        = 16
	adidCipherLen           = 16
	adidIntegritySignOffset = 32
	adidIntegritySignLen    = 4

	adidBufPadOffset     = 0
	adidBufPadLen        = 20
	adidBufPayloadOffset = 20
	adidBufPayloadLen    = 16
	adidBufSignOffset    = 36
	adidBufSignLen       = 20 // integrity signature needs only 4 bytes buffer, but hmac makes 20-bytes array by default
	adidBufLen           = adidBufPadLen + adidBufPayloadLen + adidBufSignLen
)

type AdID struct {
	DoubleClick
}

var (
	ErrBadAdIDLen = errors.New(fmt.Sprintf("message length must be %d", adidMsgLen))

	adidResetBuf = make([]byte, adidBufLen)
)

func NewAdID(encryptionKey, integrityKey []byte) *AdID {
	a := &AdID{}
	a.SetKeys(encryptionKey, integrityKey)
	return a
}

func (a *AdID) Encrypt(dst, rawAdID []byte) ([]byte, error) {
	_ = rawAdID
	return dst, nil
}

func (a *AdID) Decrypt(dst, encryptedAdID []byte, uuid bool) ([]byte, error) {
	if len(encryptedAdID) != adidMsgLen {
		return dst, ErrBadAdIDLen
	}

	initVector := encryptedAdID[adidInitVectorOffset:adidInitVectorLen]
	cipherText := encryptedAdID[adidCipherOffset : adidCipherOffset+adidCipherLen]
	integritySign := encryptedAdID[adidIntegritySignOffset : adidIntegritySignOffset+adidIntegritySignLen]

	// Prepare buffer.
	if len(a.buf) < adidBufLen {
		a.buf = append(a.buf, make([]byte, adidBufLen-len(a.buf))...)
	}

	// Init encryption hmac.
	if a.hmacE == nil {
		a.hmacE = hmac.New(sha1.New, a.encryptionKey)
	}
	// Compute pad.
	pad := a.buf[adidBufPadOffset:adidBufPadLen]
	a.hmacE.Reset()
	a.hmacE.Write(initVector)
	pad = a.hmacE.Sum(pad[:0])

	// Apply xor to reverse encryption.
	payload := a.buf[adidBufPayloadOffset : adidBufPayloadOffset+adidBufPayloadLen]
	for i := 0; i < adidCipherLen; i++ {
		payload[i] = cipherText[i] ^ pad[i]
	}

	// Init encryption hmac.
	if a.hmacI == nil {
		a.hmacI = hmac.New(sha1.New, a.integrityKey)
	}
	// Compute signature.
	computedSign := a.buf[adidBufSignOffset : adidBufSignOffset+adidBufSignLen]
	a.hmacI.Reset()
	a.hmacI.Write(payload)
	a.hmacI.Write(initVector)
	computedSign = a.hmacI.Sum(computedSign[:0])[:adidIntegritySignLen]
	if !hmac.Equal(computedSign, integritySign) {
		return dst, ErrSignCheckFail
	}

	if uuid {
		// Convert payload to UUID.
		for i := 0; i < adidBufPayloadLen; i++ {
			switch i {
			case uuidDashPosTimeLow, uuidDashPosTimeMid, uuidDashPosTimeHiAndVer, uuidDashPosClockSeq:
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

func (a *AdID) Reset() {
	a.buf = append(a.buf[:0], adidResetBuf...)
}
