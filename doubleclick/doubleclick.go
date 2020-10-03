package doubleclick

import (
	"errors"
	"hash"
)

const (
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
