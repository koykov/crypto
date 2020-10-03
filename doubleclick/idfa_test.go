package doubleclick

import (
	"bytes"
	"testing"
)

var (
	encryptedIdfa = []byte{
		0x38, 0x6e, 0x3a, 0xc0, 0x00, 0x0c, 0x0a, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef, 0xe9, 0x8c, 0xc9, 0x46, 0x57, 0x3f, 0xbf, 0x46, 0x57, 0x95, 0xcc, 0x10,
	}
	decryptedIdfa = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
)

func TestIdfa_Decrypt(t *testing.T) {
	i := NewIdfa(encryptionKey, integrityKey)
	var (
		dst []byte
		err error
	)
	dst, err = i.Decrypt(dst, encryptedIdfa)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(dst, decryptedIdfa) {
		t.Error("decrypt Idfa failed")
	}
}

func BenchmarkIdfa_Decrypt(b *testing.B) {
	x := NewIdfa(encryptionKey, integrityKey)
	var (
		dst []byte
		err error
	)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dst = dst[:0]
		dst, err = x.Decrypt(dst, encryptedIdfa)
		if err != nil {
			b.Error(err)
		}
		if !bytes.Equal(dst, decryptedIdfa) {
			b.Error("decrypt Idfa failed")
		}
		x.Reset()
	}
}

func benchmarkIdfaDecryptParallel(b *testing.B, n int) {
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		var (
			dst []byte
			err error
		)
		for pb.Next() {
			for i := 0; i < n; i++ {
				a := AcquireIdfa(encryptionKey, integrityKey)

				dst = dst[:0]
				dst, err = a.Decrypt(dst, encryptedIdfa)
				if err != nil {
					b.Error(err)
				}
				if !bytes.Equal(dst, decryptedIdfa) {
					b.Error("decrypt Idfa failed")
				}

				ReleaseIdfa(a)
			}
		}
	})
}

func BenchmarkIdfa_DecryptParallel1(b *testing.B) {
	benchmarkIdfaDecryptParallel(b, 1)
}

func BenchmarkIdfa_DecryptParallel10(b *testing.B) {
	benchmarkIdfaDecryptParallel(b, 10)
}

func BenchmarkIdfa_DecryptParallel100(b *testing.B) {
	benchmarkIdfaDecryptParallel(b, 100)
}

func BenchmarkIdfa_DecryptParallel1000(b *testing.B) {
	benchmarkIdfaDecryptParallel(b, 1000)
}
