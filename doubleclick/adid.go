package doubleclick

import (
	"errors"
	"fmt"
)

const (
	adidMsgLen    = 36
	adidCipherLen = 16
	// integrity signature needs only 4 bytes buffer, but hmac makes 20-bytes array by default
	adidBufLen = 56 // adidBufPadLen + adidBufPayloadLen + adidBufSignLen
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

	var err error
	dst, err = a.decrypt(dst, encryptedAdID, adidCipherLen)
	if err != nil {
		return dst, err
	}

	if uuid {
		// Convert payload to UUID.
		a.buf = append(a.buf[:0], dst...)
		dst = dst[:0]
		for i := 0; i < adidCipherLen; i++ {
			switch i {
			case uuidDashPosTimeLow, uuidDashPosTimeMid, uuidDashPosTimeHiAndVer, uuidDashPosClockSeq:
				dst = append(dst, '-')
			}
			dst = append(dst, hextable[a.buf[i]>>4])
			dst = append(dst, hextable[a.buf[i]&0x0f])
		}
	}
	return dst, nil
}

func (a *AdID) Reset() {
	a.buf = append(a.buf[:0], adidResetBuf...)
}
