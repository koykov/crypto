package doubleclick

import (
	"errors"
	"fmt"
)

const (
	idfaMsgLen    = 28
	idfaCipherLen = 8
	// integrity signature needs only 4 bytes buffer, but hmac makes 20-bytes array by default
	idfaBufLen = 48 // idfaBufPadLen + idfaBufPayloadLen + idfaBufSignLen
)

type Idfa struct {
	DoubleClick
}

var (
	ErrBadIdfaLen = errors.New(fmt.Sprintf("message length must be %d", idfaMsgLen))

	idfaResetBuf = make([]byte, idfaBufLen)
)

func NewIdfa(encryptionKey, integrityKey []byte) *Idfa {
	i := &Idfa{}
	i.SetKeys(encryptionKey, integrityKey)
	return i
}

func (i *Idfa) Encrypt(dst, rawIdfa []byte) ([]byte, error) {
	_ = rawIdfa
	return dst, nil
}

func (i *Idfa) Decrypt(dst, encryptedIdfa []byte) ([]byte, error) {
	if len(encryptedIdfa) != idfaMsgLen {
		return dst, ErrBadIdfaLen
	}

	var err error
	dst, err = i.decrypt(dst, encryptedIdfa, idfaCipherLen)
	if err != nil {
		return dst, err
	}

	return dst, nil
}

func (i *Idfa) Reset() {
	i.buf = append(i.buf[:0], idfaResetBuf...)
}
