package doubleclick

const (
	// Hex symbols.
	hextable = "0123456789abcdef"
	// UUID dash positions.
	dashPosTimeLow      = 4
	dashPosTimeMid      = 6
	dashPosTimeHiAndVer = 8
	dashPosClockSeq     = 10
)

// The signature of convert function.
type ConvFn func(dst, src []byte) []byte

// Convert payload to UUID.
func ConvPayloadToUUID(dst, src []byte) []byte {
	_ = src[len(src)-1]
	for i := 0; i < len(src); i++ {
		switch i {
		case dashPosTimeLow, dashPosTimeMid, dashPosTimeHiAndVer, dashPosClockSeq:
			dst = append(dst, '-')
		}
		dst = append(dst, hextable[src[i]>>4])
		dst = append(dst, hextable[src[i]&0x0f])
	}
	return dst
}
