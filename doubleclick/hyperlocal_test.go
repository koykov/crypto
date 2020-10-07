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

func TestDecryptHyperlocal(t *testing.T) {
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
}

func BenchmarkDecryptHyperlocal(b *testing.B) {
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
}

func benchmarkHyperlocalDecryptParallel(b *testing.B, n int) {
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

func BenchmarkDecryptHyperlocalParallel1(b *testing.B) {
	benchmarkHyperlocalDecryptParallel(b, 1)
}

func BenchmarkDecryptHyperlocalParallel10(b *testing.B) {
	benchmarkHyperlocalDecryptParallel(b, 10)
}

func BenchmarkDecryptHyperlocalParallel100(b *testing.B) {
	benchmarkHyperlocalDecryptParallel(b, 100)
}

func BenchmarkDecryptHyperlocalParallel1000(b *testing.B) {
	benchmarkHyperlocalDecryptParallel(b, 1000)
}
