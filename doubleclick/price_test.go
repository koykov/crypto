package doubleclick

import (
	"testing"
)

var (
	encryptedPrice = []byte{
		0x38, 0x6e, 0x3a, 0xc0, 0x00, 0x0c, 0x0a, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef, 0xe9, 0x8d, 0xcb, 0x45, 0x53, 0x28, 0xf6, 0xc1, 0xde, 0x8e, 0x42, 0x31,
	}
	decryptedPrice = 1.2
	micros         = 1e6
)

func TestDecryptPrice(t *testing.T) {
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
}

func BenchmarkDecryptPrice(b *testing.B) {
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
}

func benchmarkPriceDecryptParallel(b *testing.B, n int) {
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

func BenchmarkDecryptPriceParallel1(b *testing.B) {
	benchmarkPriceDecryptParallel(b, 1)
}

func BenchmarkDecryptPriceParallel10(b *testing.B) {
	benchmarkPriceDecryptParallel(b, 10)
}

func BenchmarkDecryptPriceParallel100(b *testing.B) {
	benchmarkPriceDecryptParallel(b, 100)
}

func BenchmarkDecryptPriceParallel1000(b *testing.B) {
	benchmarkPriceDecryptParallel(b, 1000)
}
