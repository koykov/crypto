package doubleclick

import (
	"bytes"
	"testing"
)

var (
	encryptedHyperlocal = []byte{
		0x38, 0x6e, 0x3a, 0xc0, 0x00, 0x0c, 0x0a, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfb, 0x87, 0xc6, 0x45, 0x53, 0x0e, 0xfb, 0x54, 0x4d, 0xe6, 0x38, 0x42, 0xa6, 0x09, 0xcc, 0x0c,
	}
	decryptedHyperlocal = []byte{
		0x12, 0x0a, 0x0d, 0x00, 0x00, 0x34, 0x42, 0x15, 0x00, 0x00, 0x34, 0x42,
	}
)

func TestHyperlocal(t *testing.T) {
	t.Run("decrypt", func(t *testing.T) {
		d := New(TypeHyperlocal, encryptionKey, integrityKey)
		var (
			dst []byte
			err error
		)
		dst, err = d.Decrypt(dst, encryptedHyperlocal)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(dst, decryptedHyperlocal) {
			t.Error("decrypt hyperlocal failed")
		}
	})
	t.Run("encrypt", func(t *testing.T) {
		d := New(TypeHyperlocal, encryptionKey, integrityKey)
		var (
			dst []byte
			err error
		)
		dst, err = d.Encrypt(dst, initVector, decryptedHyperlocal)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(dst, encryptedHyperlocal) {
			t.Error("encrypt hyperlocal failed")
		}
	})
}

func BenchmarkHyperlocal(b *testing.B) {
	b.Run("decrypt", func(b *testing.B) {
		d := New(TypeHyperlocal, encryptionKey, integrityKey)
		var (
			dst []byte
			err error
		)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			dst = dst[:0]
			dst, err = d.Decrypt(dst, encryptedHyperlocal)
			if err != nil {
				b.Error(err)
			}
			if !bytes.Equal(dst, decryptedHyperlocal) {
				b.Error("decrypt Hyperlocal failed")
			}
			d.Reset()
		}
	})
	b.Run("encrypt", func(b *testing.B) {
		d := New(TypeHyperlocal, encryptionKey, integrityKey)
		var (
			dst []byte
			err error
		)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			dst = dst[:0]
			dst, err = d.Encrypt(dst, initVector, decryptedHyperlocal)
			if err != nil {
				b.Error(err)
			}
			if !bytes.Equal(dst, encryptedHyperlocal) {
				b.Error("encrypt hyperlocal failed")
			}
			d.Reset()
		}
	})

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
					d := Acquire(TypeHyperlocal, encryptionKey, integrityKey)

					dst = dst[:0]
					dst, err = d.Decrypt(dst, encryptedHyperlocal)
					if err != nil {
						b.Error(err)
					}
					if !bytes.Equal(dst, decryptedHyperlocal) {
						b.Error("decrypt hyperlocal failed")
					}

					Release(d)
				}
			}
		})
	}
	b.Run("decrypt parallel 1", func(b *testing.B) { decFn(b, 1) })
	b.Run("decrypt parallel 10", func(b *testing.B) { decFn(b, 10) })
	b.Run("decrypt parallel 100", func(b *testing.B) { decFn(b, 100) })
	b.Run("decrypt parallel 1000", func(b *testing.B) { decFn(b, 1000) })

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
					d := Acquire(TypeHyperlocal, encryptionKey, integrityKey)

					dst = dst[:0]
					dst, err = d.Encrypt(dst, initVector, decryptedHyperlocal)
					if err != nil {
						b.Error(err)
					}
					if !bytes.Equal(dst, encryptedHyperlocal) {
						b.Error("encrypt hyperlocal failed")
					}

					Release(d)
				}
			}
		})
	}
	b.Run("encrypt parallel 1", func(b *testing.B) { encFn(b, 1) })
	b.Run("encrypt parallel 10", func(b *testing.B) { encFn(b, 10) })
	b.Run("encrypt parallel 100", func(b *testing.B) { encFn(b, 100) })
	b.Run("encrypt parallel 1000", func(b *testing.B) { encFn(b, 1000) })
}
