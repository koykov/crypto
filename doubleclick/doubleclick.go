package doubleclick

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"hash"
)

// Type is a type constant of supported DoubleClick types.
type Type int

const (
	// TypeAdID  is an Advertising ID
	// https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-advertising-id
	TypeAdID Type = iota
	// TypeIDFA is an iOS ID for advertisers
	// https://support.google.com/authorizedbuyers/answer/3221407
	TypeIDFA
	// TypePrice is an Ad Exchange RTB protocol price
	// https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-price
	TypePrice
	// TypeHyperlocal is a Hyperlocal Targeting Signals
	// https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-hyperlocal
	TypeHyperlocal

	// Message bounds
	initVectorOffset = 0
	initVectorLen    = 16
	cipherOffset     = 16
	integritySignLen = 4
	// Buffer bounds
	bufPadOffset     = 0
	bufPadLen        = 20
	bufPayloadOffset = 20
	bufSignLen       = 20 // integrity signature needs only 4 bytes buffer, but hmac makes 20-bytes array by default

	// AdID message and payload length
	msgLenAdID     = 36
	payloadLenAdID = 16
	// IDFA message and payload length
	msgLenIDFA     = 28
	payloadLenIDFA = 8
	// Hyperlocal message and payload length
	msgLenHyperlocal     = 32
	payloadLenHyperlocal = 12
	// Price message and payload length
	msgLenPrice     = 28
	payloadLenPrice = 8
)

// DoubleClick is an encryption and decryption support for the DoubleClick Ad Exchange RTB protocol.
//
// Encrypted payloads are wrapped by "packages" in the general format:
// initVector:16 || E(payload:?) || I(signature:4)
// where:
// * initVector = timestamp:8 || serverId:8} (AdX convention)
// * E(payload) = payload ^ hmac(encryptionKey, initVector)} per max-20-byte block
// * I(signature) = hmac(integrityKey, payload || initVector)[0..3]}
//
// This tool is thread-safe when use it together with pool.
type DoubleClick struct {
	typ Type
	// Encryption and integrity HMAC instances.
	hmacE, hmacI hash.Hash
	// Byte buffer.
	buf []byte
}

var b64Pad = []byte("=")

// New makes new instance of DoubleClick.
//
// Better use pool instead of direct using New().
func New(typ Type, encryptionKey, integrityKey []byte) *DoubleClick {
	d := &DoubleClick{typ: typ}
	d.SetKeys(encryptionKey, integrityKey)
	return d
}

// SetKeys sets encryption and integrity keys.
//
// During first keys set will be initialized HMAC helpers.
func (d *DoubleClick) SetKeys(encryptionKey, integrityKey []byte) {
	// Init encryption hmac.
	if d.hmacE == nil {
		d.hmacE = hmac.New(sha1.New, encryptionKey)
	}
	// Init integrity hmac.
	if d.hmacI == nil {
		d.hmacI = hmac.New(sha1.New, integrityKey)
	}
}

// Encrypt is a common encryption method.
//
// Encrypts plain to dst using initVec.
func (d *DoubleClick) Encrypt(dst, initVec, plain []byte) ([]byte, error) {
	return d.EncryptFn(dst, initVec, plain, nil)
}

// EncryptFn performs encryption and apply post-encryption convert func.
func (d *DoubleClick) EncryptFn(dst, initVec, plain []byte, convFn ConvFn) ([]byte, error) {
	var plainLen int
	switch d.typ {
	case TypeAdID:
		plainLen = payloadLenAdID
	case TypeIDFA:
		plainLen = payloadLenIDFA
	case TypePrice:
		plainLen = payloadLenPrice
	case TypeHyperlocal:
		plainLen = payloadLenHyperlocal
	default:
		return dst, ErrUnkType
	}

	if len(plain) != plainLen {
		return dst, ErrBadPlainLen
	}

	return d.encrypt(dst, initVec, plain, plainLen, convFn)
}

// EncryptPrice is a price encryption method.
//
// See https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-price for details.
func (d *DoubleClick) EncryptPrice(price float64, dst, initVec []byte, micros int) ([]byte, error) {
	// Apply micros.
	uprice := uint64(price * float64(micros))
	// Increase buffer with +1 payload length and use extra space as an intermediate source array.
	bufLen := bufPadLen + payloadLenPrice + bufSignLen
	doubleBufLen := bufLen + payloadLenPrice
	if len(d.buf) < doubleBufLen {
		d.buf = append(d.buf, make([]byte, doubleBufLen-len(d.buf))...)
	}
	// Source buffer.
	bprice := d.buf[bufLen:doubleBufLen]
	binary.BigEndian.PutUint64(bprice, uprice)

	d.typ = TypePrice
	return d.EncryptFn(dst, initVec, bprice, nil)
}

// Common encryption helper.
func (d *DoubleClick) encrypt(dst, initVec, plain []byte, plainLen int, convFn ConvFn) ([]byte, error) {
	// Check init vector length.
	if len(initVec) != initVectorLen {
		return dst, ErrBadInitvLen
	}

	// Prepare buffer.
	bufLen := bufPadLen + plainLen + bufSignLen
	if len(d.buf) < bufLen {
		d.buf = append(d.buf, make([]byte, bufLen-len(d.buf))...)
	}

	// Compute pad.
	pad := d.buf[bufPadOffset:bufPadLen]
	d.hmacE.Reset()
	d.hmacE.Write(initVec)
	pad = d.hmacE.Sum(pad[:0])[:initVectorLen]

	// Apply xor to do encryption.
	cipher := d.buf[bufPayloadOffset : bufPayloadOffset+plainLen]
	for i := 0; i < plainLen; i++ {
		cipher[i] = pad[i] ^ plain[i]
	}

	// Compute signature.
	bufSignOffset := bufPayloadOffset + plainLen
	computedSign := d.buf[bufSignOffset : bufSignOffset+bufSignLen]
	d.hmacI.Reset()
	d.hmacI.Write(plain)
	d.hmacI.Write(initVec)
	computedSign = d.hmacI.Sum(computedSign[:0])[:integritySignLen]

	// Fill destination array.
	dst = append(dst[:0], initVec...)
	dst = append(dst, cipher...)
	dst = append(dst, computedSign...)

	// Check and apply convert func.
	if convFn != nil {
		d.buf = append(d.buf[:0], dst...)
		dst = convFn(dst[:0], d.buf)
	}

	return dst, nil
}

// Decrypt is a common decryption method.
//
// Decrypts cipher to dst.
func (d *DoubleClick) Decrypt(dst, cipher []byte) ([]byte, error) {
	return d.DecryptFn(dst, cipher, nil)
}

// DecryptFn performs decryption and apply post-decryption convert func.
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
	case TypeHyperlocal:
		msgLen = msgLenHyperlocal
		payloadLen = payloadLenHyperlocal
	default:
		return dst, ErrUnkType
	}

	if len(cipher) != msgLen {
		return dst, ErrBadMsgLen
	}

	return d.decrypt(dst, cipher, payloadLen, convFn)
}

// DecryptPrice is a price decryption method.
//
// See https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-price for details.
func (d *DoubleClick) DecryptPrice(cipher []byte, micros int) (float64, error) {
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
	return float64(price) / float64(micros), nil
}

// Common decryption helper.
func (d *DoubleClick) decrypt(dst, cipher []byte, payloadLen int, convFn ConvFn) ([]byte, error) {
	// Split message to parts (init vector, payload, integrity sign).
	initVector := cipher[initVectorOffset:initVectorLen]
	cipherText := cipher[cipherOffset : cipherOffset+payloadLen]
	integritySignOffset := cipherOffset + payloadLen
	integritySign := cipher[integritySignOffset : integritySignOffset+integritySignLen]

	// Prepare buffer.
	bufLen := bufPadLen + payloadLen + bufSignLen
	if len(d.buf) < bufLen {
		d.buf = append(d.buf, make([]byte, bufLen-len(d.buf))...)
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

	// Check and apply convert func
	if convFn != nil {
		dst = convFn(dst, payload)
	} else {
		// ... or copy payload to destination array.
		dst = append(dst, payload...)
	}
	return dst, nil
}

// WebSafeEncode encodes string to web-safe base64.
//
// Note that this method will trim base64 paddings.
func (d *DoubleClick) WebSafeEncode(dst, plain []byte) ([]byte, error) {
	// Get length of further encoded result.
	n := base64.StdEncoding.EncodedLen(len(plain))
	// Prepare buffer.
	if len(d.buf) < n {
		d.buf = append(d.buf, make([]byte, n-len(d.buf))...)
	}
	// Encode to buffer.
	base64.StdEncoding.Encode(d.buf, plain)
	// Get index of base64 padding.
	p := bytes.Index(d.buf, b64Pad)
	if p < 0 {
		return dst, ErrNegativePad
	}
	// Fill up destination array with encoded string except paddings.
	dst = append(dst[:0], d.buf[:p]...)
	return dst, nil
}

// WebSafeDecode decodes web-safe base64 string.
//
// Input string must not contain base64 paddings.
func (d *DoubleClick) WebSafeDecode(dst, wsStr []byte) ([]byte, error) {
	n := len(wsStr)
	// Prepare buffer with double length of the input string.
	// The first half will used to restore base64 paddings.
	// The second half will used as intermediate destination array.
	if len(d.buf) < n*2 {
		d.buf = append(d.buf, make([]byte, n*2)...)
	}
	// Copy input string to buffer.
	copy(d.buf, wsStr)
	// Restore paddings.
	switch {
	case n%4 == 2:
		d.buf[n], d.buf[n+1] = '=', '='
		n += 2
	case n%4 == 3:
		d.buf[n] = '='
		n++
	}
	// Restore + and / symbols.
	for i := 0; i < n; i++ {
		switch d.buf[i] {
		case '-':
			d.buf[i] = '+'
		case '_':
			d.buf[i] = '/'
		}
	}

	// Get potential length of result.
	k := base64.StdEncoding.DecodedLen(n)
	// Decode restored string to the second half of buffer and get final length of result.
	c, err := base64.StdEncoding.Decode(d.buf[n:n+k], d.buf[:n])
	if err != nil {
		return dst, err
	}
	// Fill up destination array with decoded string.
	dst = append(dst, d.buf[n:n+c]...)
	return dst, nil
}

// Reset buffer.
func (d *DoubleClick) Reset() {
	_ = d.buf[len(d.buf)-1]
	for i := range d.buf {
		d.buf[i] = 0
	}
}
