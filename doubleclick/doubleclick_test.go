package doubleclick

import (
	"bytes"
	"testing"
)

var (
	encryptionKey = []byte{
		0xb0, 0x8c, 0x70, 0xcf, 0xbc, 0xb0, 0xeb, 0x6c, 0xab, 0x7e, 0x82, 0xc6, 0xb7, 0x5d, 0xa5, 0x20,
		0x72, 0xae, 0x62, 0xb2, 0xbf, 0x4b, 0x99, 0x0b, 0xb8, 0x0a, 0x48, 0xd8, 0x14, 0x1e, 0xec, 0x07,
	}
	integrityKey = []byte{
		0xbf, 0x77, 0xec, 0x55, 0xc3, 0x01, 0x30, 0xc1, 0xd8, 0xcd, 0x18, 0x62, 0xed, 0x2a, 0x4c, 0xd2,
		0xc7, 0x6a, 0xc3, 0x3b, 0xc0, 0xc4, 0xce, 0x8a, 0x3d, 0x3b, 0xbd, 0x3a, 0xd5, 0x68, 0x77, 0x92,
	}

	encryptedID = []byte{
		0x38, 0x6e, 0x3a, 0xc0, 0x00, 0x0c, 0x0a, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xe9, 0x8c,
		0xc9, 0x46, 0x57, 0x3f, 0xbf, 0x46, 0x45, 0xef, 0x06, 0x0b, 0x17, 0xa6, 0x67, 0xa6, 0x17, 0xc6, 0x6b, 0xcb,
	}
	decryptedID   = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	decryptedUUID = []byte("00010203-0405-0607-0809-0a0b0c0d0e0f")
)

func TestDoubleClick_Decrypt(t *testing.T) {
	d := New(encryptionKey, integrityKey)
	var (
		dst AdvertisingID
		err error
	)
	dst, err = d.AppendDecrypt(dst, encryptedID)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(dst, decryptedID) {
		t.Error("decrypt ID failed")
	}
	if !bytes.Equal(dst.UUID(), decryptedUUID) {
		t.Error("decrypt UUID failed")
	}
}

func BenchmarkDoubleClick_Decrypt(b *testing.B) {
	d := New(encryptionKey, integrityKey)
	var (
		dst AdvertisingID
		err error
	)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dst = dst[:0]
		dst, err = d.AppendDecrypt(dst, encryptedID)
		if err != nil {
			b.Error(err)
		}
		if !bytes.Equal(dst, decryptedID) {
			b.Error("decrypt ID failed")
		}
		if !bytes.Equal(dst.UUID(), decryptedUUID) {
			b.Error("decrypt UUID failed")
		}
		d.Reset()
	}
}

func benchmarkDecryptParallel(b *testing.B, n int) {
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		var (
			dst AdvertisingID
			err error
		)
		for pb.Next() {
			for i := 0; i < n; i++ {
				d := Acquire(encryptionKey, integrityKey)

				dst = dst[:0]
				dst, err = d.AppendDecrypt(dst, encryptedID)
				if err != nil {
					b.Error(err)
				}
				if !bytes.Equal(dst, decryptedID) {
					b.Error("decrypt ID failed")
				}
				if !bytes.Equal(dst.UUID(), decryptedUUID) {
					b.Error("decrypt UUID failed")
				}

				Release(d)
			}
		}
	})
}

func BenchmarkDoubleClick_DecryptParallel1(b *testing.B) {
	benchmarkDecryptParallel(b, 1)
}

func BenchmarkDoubleClick_DecryptParallel10(b *testing.B) {
	benchmarkDecryptParallel(b, 10)
}

func BenchmarkDoubleClick_DecryptParallel100(b *testing.B) {
	benchmarkDecryptParallel(b, 100)
}

func BenchmarkDoubleClick_DecryptParallel1000(b *testing.B) {
	benchmarkDecryptParallel(b, 1000)
}
