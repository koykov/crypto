package doubleclick

import "errors"

var (
	ErrUnkType       = errors.New("unknown type")
	ErrBadInitvLen   = errors.New("unsupported init vector length")
	ErrBadMsgLen     = errors.New("unsupported message length")
	ErrBadPlainLen   = errors.New("unsupported plain source length")
	ErrSignCheckFail = errors.New("signature check failed")
	ErrNegativePad   = errors.New("negative base64 pad index")
)
