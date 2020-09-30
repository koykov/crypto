package gaid

import "errors"

const (
	KeyAlgorithm = "HmacSHA1"

	InitVectorBase            = 0
	InitVectorSize            = 16
	InitVectorTimestampOffset = 0
	InitVectorServerIdOffset  = 8

	PayloadBase   = InitVectorBase + InitVectorSize
	SignatureSize = 4
	OverheadSize  = InitVectorSize + SignatureSize

	CounterPagesize = 20
	CounterSections = 3*256 + 1

	MicrosPerCurrencyUnit = 1000000
)

var (
	ErrCipherOverheadSize = errors.New("cipher data is too long")
)

func Decrypt(cipher []byte) ([]byte, error) {
	var dst []byte
	return AppendDecrypt(dst, cipher)
}

func AppendDecrypt(dst, cipher []byte) ([]byte, error) {
	if len(cipher) > OverheadSize {
		return nil, ErrCipherOverheadSize
	}

	//

	return nil, nil
}
