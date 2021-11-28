package doubleclick

import (
	"bytes"
	"testing"
)

var (
	webSafeStr  = []byte("X3XP0gALeh0KGHxDAAAieJQuL5DiDt8XuzHvaw")
	nwebSafeStr = []byte{
		0x5f, 0x75, 0xcf, 0xd2, 0x00, 0x0b, 0x7a, 0x1d, 0x0a, 0x18, 0x7c, 0x43, 0x00, 0x00,
		0x22, 0x78, 0x94, 0x2e, 0x2f, 0x90, 0xe2, 0x0e, 0xdf, 0x17, 0xbb, 0x31, 0xef, 0x6b,
	}
)

func TestWebSafe(t *testing.T) {
	t.Run("decode", func(t *testing.T) {
		d := New(TypePrice, encryptionKey, integrityKey)
		var (
			dst []byte
			err error
		)
		dst, err = d.WebSafeDecode(dst, webSafeStr)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(dst, nwebSafeStr) {
			t.Error("web safe decode failed")
		}
	})
	t.Run("encode", func(t *testing.T) {
		d := New(TypePrice, encryptionKey, integrityKey)
		var (
			dst []byte
			err error
		)
		dst, err = d.WebSafeEncode(dst, nwebSafeStr)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(dst, webSafeStr) {
			t.Error("web safe encode failed")
		}
	})
}

func BenchmarkWebSafeDecode(b *testing.B) {
	var (
		dst []byte
		err error
	)
	d := New(TypePrice, encryptionKey, integrityKey)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dst = dst[:0]
		dst, err = d.WebSafeDecode(dst, webSafeStr)
		if err != nil {
			b.Error(err)
		}
		if !bytes.Equal(dst, nwebSafeStr) {
			b.Error("web safe decode failed")
		}
	}
}

func BenchmarkWebSafeEncode(b *testing.B) {
	var (
		dst []byte
		err error
	)
	d := New(TypePrice, encryptionKey, integrityKey)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dst = dst[:0]
		dst, err = d.WebSafeEncode(dst, nwebSafeStr)
		if err != nil {
			b.Error(err)
		}
		if !bytes.Equal(dst, webSafeStr) {
			b.Error("web safe encode failed")
		}
	}
}
