package doubleclick

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"unsafe"

	"github.com/koykov/fastconv"
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

	uuidDashPosTimeLow      = 4
	uuidDashPosTimeMid      = 6
	uuidDashPosTimeHiAndVer = 8
	uuidDashPosClockSeq     = 10
	uuidLen                 = 36
	uuidBufOffset           = 16
	uuidBufLen              = 36
)

type DoubleClick struct {
	hmacE, hmacI hash.Hash

	buf, encryptionKey, integrityKey []byte
}

type AdvertisingID []byte

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

func (d *DoubleClick) Decrypt(encryptedID []byte) (AdvertisingID, error) {
	var dst AdvertisingID
	return d.decrypt(dst, encryptedID)
}

func (d *DoubleClick) AppendDecrypt(dst, encryptedID []byte) (AdvertisingID, error) {
	return d.decrypt(dst, encryptedID)
}

func (d *DoubleClick) decrypt(dst, encryptedID []byte) (AdvertisingID, error) {
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

	dst = append(dst[:0], payload...)
	return dst, nil
}

func (d *DoubleClick) Reset() {
	d.buf = append(d.buf[:0], resetBuf...)
}

func (a *AdvertisingID) UUID() []byte {
	self := (*a)[0:bufPayloadLen]
	for i := 0; i < bufPayloadLen; i++ {
		switch i {
		case uuidDashPosTimeLow, uuidDashPosTimeMid, uuidDashPosTimeHiAndVer, uuidDashPosClockSeq:
			self = append(self, '-')
		}
		self = append(self, hextable[self[i]>>4])
		self = append(self, hextable[self[i]&0x0f])
	}
	copy(self[0:uuidLen], self[uuidBufOffset:uuidBufOffset+uuidBufLen])

	*a = append((*a)[:0], self...)
	a.resetLen()
	return *a
}

func (a *AdvertisingID) resetLen() {
	h := *(*reflect.SliceHeader)(unsafe.Pointer(a))
	if h.Cap >= uuidLen {
		h.Len = uuidLen
	}
	*a = *(*[]byte)(unsafe.Pointer(&h))
}

func (a *AdvertisingID) String() string {
	return fastconv.B2S(*a)
}
