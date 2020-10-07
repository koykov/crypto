package doubleclick

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash"
)

const (
	TypeAdID Type = iota
	TypeIDFA
	TypePrice

	initVectorOffset = 0
	initVectorLen    = 16
	cipherOffset     = 16
	integritySignLen = 4

	bufPadOffset     = 0
	bufPadLen        = 20
	bufPayloadOffset = 20
	bufSignLen       = 20 // integrity signature needs only 4 bytes buffer, but hmac makes 20-bytes array by default

	msgLenAdID     = 36
	payloadLenAdID = 16

	msgLenIDFA     = 28
	payloadLenIDFA = 8

	msgLenPrice     = 28
	payloadLenPrice = 8
)

type Type int

type DoubleClick struct {
	typ          Type
	hmacE, hmacI hash.Hash

	buf, encryptionKey, integrityKey []byte
}

var (
	ErrUnkType       = errors.New("unknown decryptor type")
	ErrBadMsgLen     = errors.New("unsupported message length")
	ErrSignCheckFail = errors.New("signature check failed")
)

func New(typ Type, encryptionKey, integrityKey []byte) *DoubleClick {
	d := &DoubleClick{typ: typ}
	d.SetKeys(encryptionKey, integrityKey)
	return d
}

func (d *DoubleClick) SetKeys(encryptionKey, integrityKey []byte) {
	d.encryptionKey, d.integrityKey = encryptionKey, integrityKey
}

func (d *DoubleClick) Decrypt(dst, cipher []byte) ([]byte, error) {
	return d.DecryptFn(dst, cipher, nil)
}

func (d *DoubleClick) DecryptFn(dst, cipher []byte, convFn ConvFn) ([]byte, error) {
	var (
		msgLen, payloadLen int
	)
	switch d.typ {
	case TypeAdID:
		msgLen = msgLenAdID
		payloadLen = payloadLenAdID
	case TypeIDFA:
		msgLen = msgLenIDFA
		payloadLen = payloadLenIDFA
	case TypePrice:
		msgLen = msgLenPrice
		payloadLen = payloadLenPrice
	default:
		return dst, ErrUnkType
	}

	if len(cipher) != msgLen {
		return dst, ErrBadMsgLen
	}

	var err error
	dst, err = d.decrypt(dst, cipher, payloadLen, convFn)
	if err != nil {
		return dst, err
	}

	return dst, nil
}

func (d *DoubleClick) DecryptPrice(cipher []byte, micros float64) (float64, error) {
	// Increase buffer with +1 payload length and use extra space as a destination array.
	bufLen := bufPadLen + payloadLenPrice + bufSignLen
	doubleBufLen := bufLen + payloadLenPrice
	if len(d.buf) < doubleBufLen {
		d.buf = append(d.buf, make([]byte, doubleBufLen-len(d.buf))...)
	}

	dst := d.buf[bufLen:doubleBufLen]
	decrypted, err := d.DecryptFn(dst[:0], cipher, nil)
	if err != nil {
		return 0, err
	}

	price := binary.BigEndian.Uint64(decrypted)
	return float64(price) / micros, nil
}

func (d *DoubleClick) decrypt(dst, cipher []byte, payloadLen int, convFn ConvFn) ([]byte, error) {
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

	if convFn != nil {
		dst = convFn(dst, payload)
	} else {
		dst = append(dst, payload...)
	}
	return dst, nil
}

func (d *DoubleClick) Reset() {
	_ = d.buf[len(d.buf)-1]
	for i := range d.buf {
		d.buf[i] = 0
	}
}
