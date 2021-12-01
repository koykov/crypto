package doubleclick

import (
	"bytes"
	"testing"
)

var (
	encryptedAdID = []byte{
		0x38, 0x6e, 0x3a, 0xc0, 0x00, 0x0c, 0x0a, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xe9, 0x8c,
		0xc9, 0x46, 0x57, 0x3f, 0xbf, 0x46, 0x45, 0xef, 0x06, 0x0b, 0x17, 0xa6, 0x67, 0xa6, 0x17, 0xc6, 0x6b, 0xcb,
	}
	decryptedAdID   = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	decryptedAdUUID = []byte("00010203-0405-0607-0809-0a0b0c0d0e0f")
)

func TestAdID(t *testing.T) {
	t.Run("decrypt", func(t *testing.T) {
		d := New(TypeAdID, encryptionKey, integrityKey)
		var (
			dst []byte
			err error
		)
		dst, err = d.Decrypt(dst, encryptedAdID)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(dst, decryptedAdID) {
			t.Error("decrypt AdID failed")
		}
		dst, _ = d.DecryptFn(dst[:0], encryptedAdID, ConvPayloadToUUID)
		if !bytes.Equal(dst, decryptedAdUUID) {
			t.Error("decrypt AdID UUID failed")
		}
	})
	t.Run("encrypt", func(t *testing.T) {
		d := New(TypeAdID, encryptionKey, integrityKey)
		var (
			dst []byte
			err error
		)
		dst, err = d.Encrypt(dst, initVector, decryptedAdID)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(dst, encryptedAdID) {
			t.Error("encrypt AdID failed")
		}
	})
}

func BenchmarkAdID(b *testing.B) {
	b.Run("decrypt", func(b *testing.B) {
		d := New(TypeAdID, encryptionKey, integrityKey)
		var (
			dst []byte
			err error
		)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			dst = dst[:0]
			dst, err = d.DecryptFn(dst, encryptedAdID, ConvPayloadToUUID)
			if err != nil {
				b.Error(err)
			}
			if !bytes.Equal(dst, decryptedAdUUID) {
				b.Error("decrypt AdID failed")
			}
			d.Reset()
		}
	})
	b.Run("encrypt", func(b *testing.B) {
		d := New(TypeAdID, encryptionKey, integrityKey)
		var (
			dst []byte
			err error
		)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			dst = dst[:0]
			dst, err = d.Encrypt(dst, initVector, decryptedAdID)
			if err != nil {
				b.Error(err)
			}
			if !bytes.Equal(dst, encryptedAdID) {
				b.Error("encrypt AdID failed")
			}
			d.Reset()
		}
	})
}

func BenchmarkAdIDParallel(b *testing.B) {
	decFn := func(b *testing.B, n int) {
		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			var (
				dst []byte
				err error
			)
			for pb.Next() {
				for i := 0; i < n; i++ {
					d := Acquire(TypeAdID, encryptionKey, integrityKey)

					dst = dst[:0]
					dst, err = d.DecryptFn(dst, encryptedAdID, ConvPayloadToUUID)
					if err != nil {
						b.Error(err)
					}
					if !bytes.Equal(dst, decryptedAdUUID) {
						b.Error("decrypt AdID failed")
					}

					Release(d)
				}
			}
		})
	}
	b.Run("decrypt 1", func(b *testing.B) { decFn(b, 1) })
	b.Run("decrypt 10", func(b *testing.B) { decFn(b, 10) })
	b.Run("decrypt 100", func(b *testing.B) { decFn(b, 100) })
	b.Run("decrypt 1000", func(b *testing.B) { decFn(b, 1000) })

	encFn := func(b *testing.B, n int) {
		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			var (
				dst []byte
				err error
			)
			for pb.Next() {
				for i := 0; i < n; i++ {
					d := Acquire(TypeAdID, encryptionKey, integrityKey)

					dst = dst[:0]
					dst, err = d.Encrypt(dst, initVector, decryptedAdID)
					if err != nil {
						b.Error(err)
					}
					if !bytes.Equal(dst, encryptedAdID) {
						b.Error("encrypt AdID failed")
					}

					Release(d)
				}
			}
		})
	}
	b.Run("encrypt 1", func(b *testing.B) { encFn(b, 1) })
	b.Run("encrypt 10", func(b *testing.B) { encFn(b, 10) })
	b.Run("encrypt 100", func(b *testing.B) { encFn(b, 100) })
	b.Run("encrypt 1000", func(b *testing.B) { encFn(b, 1000) })
}
