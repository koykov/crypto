package doubleclick

import (
	"bytes"
	"testing"
)

var (
	encryptedPrice = []byte{
		0x38, 0x6e, 0x3a, 0xc0, 0x00, 0x0c, 0x0a, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef, 0xe9, 0x8d, 0xcb, 0x45, 0x53, 0x28, 0xf6, 0xc1, 0xde, 0x8e, 0x42, 0x31,
	}
	decryptedPrice = 1.2
	micros         = int(1e6)
)

func TestPrice(t *testing.T) {
	t.Run("decrypt", func(t *testing.T) {
		d := New(TypePrice, encryptionKey, integrityKey)
		var (
			price float64
			err   error
		)
		price, err = d.DecryptPrice(encryptedPrice, micros)
		if err != nil {
			t.Error(err)
		}
		if price != decryptedPrice {
			t.Error("decrypt price failed")
		}
	})
	t.Run("encrypt", func(t *testing.T) {
		d := New(TypePrice, encryptionKey, integrityKey)
		var (
			dst []byte
			err error
		)
		dst, err = d.EncryptPrice(decryptedPrice, dst, initVector, micros)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(dst, encryptedPrice) {
			t.Error("encrypt price failed")
		}
	})
}

func BenchmarkPrice(b *testing.B) {
	b.Run("decrypt", func(b *testing.B) {
		d := New(TypePrice, encryptionKey, integrityKey)
		var (
			price float64
			err   error
		)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			price, err = d.DecryptPrice(encryptedPrice, micros)
			if err != nil {
				b.Error(err)
			}
			if price != decryptedPrice {
				b.Error("decrypt price failed")
			}
			d.Reset()
		}
	})
	b.Run("encrypt", func(b *testing.B) {
		d := New(TypePrice, encryptionKey, integrityKey)
		var (
			dst []byte
			err error
		)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			dst = dst[:0]
			dst, err = d.EncryptPrice(decryptedPrice, dst, initVector, micros)
			if err != nil {
				b.Error(err)
			}
			if !bytes.Equal(dst, encryptedPrice) {
				b.Error("encrypt price failed")
			}
			d.Reset()
		}
	})
}

func BenchmarkPriceParallel(b *testing.B) {
	decFn := func(b *testing.B, n int) {
		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			var (
				price float64
				err   error
			)
			for pb.Next() {
				for i := 0; i < n; i++ {
					d := Acquire(TypePrice, encryptionKey, integrityKey)

					price, err = d.DecryptPrice(encryptedPrice, micros)
					if err != nil {
						b.Error(err)
					}
					if price != decryptedPrice {
						b.Error("decrypt price failed")
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
					d := Acquire(TypePrice, encryptionKey, integrityKey)

					dst = dst[:0]
					dst, err = d.EncryptPrice(decryptedPrice, dst, initVector, micros)
					if err != nil {
						b.Error(err)
					}
					if !bytes.Equal(dst, encryptedPrice) {
						b.Error("encrypt price failed")
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
