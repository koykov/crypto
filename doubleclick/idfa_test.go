package doubleclick

import (
	"bytes"
	"testing"
)

var (
	encryptedIDFA = []byte{
		0x38, 0x6e, 0x3a, 0xc0, 0x00, 0x0c, 0x0a, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef, 0xe9, 0x8c, 0xc9, 0x46, 0x57, 0x3f, 0xbf, 0x46, 0x57, 0x95, 0xcc, 0x10,
	}
	decryptedIDFA = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
)

func TestDecryptIDFA(t *testing.T) {
	d := New(TypeIDFA, encryptionKey, integrityKey)
	var (
		dst []byte
		err error
	)
	dst, err = d.Decrypt(dst, encryptedIDFA)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(dst, decryptedIDFA) {
		t.Error("decrypt IDFA failed")
	}
}

func TestEncryptIDFA(t *testing.T) {
	d := New(TypeIDFA, encryptionKey, integrityKey)
	var (
		dst []byte
		err error
	)
	dst, err = d.Encrypt(dst, initVector, decryptedIDFA)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(dst, encryptedIDFA) {
		t.Error("encrypt IDFA failed")
	}
}

func BenchmarkDecryptIDFA(b *testing.B) {
	d := New(TypeIDFA, encryptionKey, integrityKey)
	var (
		dst []byte
		err error
	)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dst = dst[:0]
		dst, err = d.Decrypt(dst, encryptedIDFA)
		if err != nil {
			b.Error(err)
		}
		if !bytes.Equal(dst, decryptedIDFA) {
			b.Error("decrypt IDFA failed")
		}
		d.Reset()
	}
}

func BenchmarkEncryptIDFA(b *testing.B) {
	d := New(TypeIDFA, encryptionKey, integrityKey)
	var (
		dst []byte
		err error
	)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dst = dst[:0]
		dst, err = d.Encrypt(dst, initVector, decryptedIDFA)
		if err != nil {
			b.Error(err)
		}
		if !bytes.Equal(dst, encryptedIDFA) {
			b.Error("encrypt IDFA failed")
		}
		d.Reset()
	}
}

func benchmarkIDFADecryptParallel(b *testing.B, n int) {
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		var (
			dst []byte
			err error
		)
		for pb.Next() {
			for i := 0; i < n; i++ {
				d := Acquire(TypeIDFA, encryptionKey, integrityKey)

				dst = dst[:0]
				dst, err = d.Decrypt(dst, encryptedIDFA)
				if err != nil {
					b.Error(err)
				}
				if !bytes.Equal(dst, decryptedIDFA) {
					b.Error("decrypt IDFA failed")
				}

				Release(d)
			}
		}
	})
}

func BenchmarkDecryptIDFAParallel1(b *testing.B) {
	benchmarkIDFADecryptParallel(b, 1)
}

func BenchmarkDecryptIDFAParallel10(b *testing.B) {
	benchmarkIDFADecryptParallel(b, 10)
}

func BenchmarkDecryptIDFAParallel100(b *testing.B) {
	benchmarkIDFADecryptParallel(b, 100)
}

func BenchmarkDecryptIDFAParallel1000(b *testing.B) {
	benchmarkIDFADecryptParallel(b, 1000)
}

func benchmarkIDFAEncryptParallel(b *testing.B, n int) {
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		var (
			dst []byte
			err error
		)
		for pb.Next() {
			for i := 0; i < n; i++ {
				d := Acquire(TypeIDFA, encryptionKey, integrityKey)

				dst = dst[:0]
				dst, err = d.Encrypt(dst, initVector, decryptedIDFA)
				if err != nil {
					b.Error(err)
				}
				if !bytes.Equal(dst, encryptedIDFA) {
					b.Error("encrypt IDFA failed")
				}

				Release(d)
			}
		}
	})
}

func BenchmarkEncryptIDFAParallel1(b *testing.B) {
	benchmarkIDFAEncryptParallel(b, 1)
}

func BenchmarkEncryptIDFAParallel10(b *testing.B) {
	benchmarkIDFAEncryptParallel(b, 10)
}

func BenchmarkEncryptIDFAParallel100(b *testing.B) {
	benchmarkIDFAEncryptParallel(b, 100)
}

func BenchmarkEncryptIDFAParallel1000(b *testing.B) {
	benchmarkIDFAEncryptParallel(b, 1000)
}
