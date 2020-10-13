package fnv

import (
	"hash/fnv"
	"testing"
)

func BenchmarkFnv32(b *testing.B) {
	p := s2b("foobar")
	r := uint32(0x31f0b262)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h := Hash32(p)
		if h != r {
			b.Error(h, "not equal to", r)
		}
	}
}

func BenchmarkFnv32Native(b *testing.B) {
	p := s2b("foobar")
	r := uint32(0x31f0b262)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		f := fnv.New32()
		_, _ = f.Write(p)
		h := f.Sum32()
		if h != r {
			b.Error(h, "not equal to", r)
		}
	}
}

func BenchmarkFnv32a(b *testing.B) {
	p := s2b("foobar")
	r := uint32(0xbf9cf968)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h := Hash32a(p)
		if h != r {
			b.Error(h, "not equal to", r)
		}
	}
}

func BenchmarkFnv32aNative(b *testing.B) {
	p := s2b("foobar")
	r := uint32(0xbf9cf968)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		f := fnv.New32a()
		_, _ = f.Write(p)
		h := f.Sum32()
		if h != r {
			b.Error(h, "not equal to", r)
		}
	}
}

func BenchmarkFnv64(b *testing.B) {
	p := s2b("foobar")
	r := uint64(0x340d8765a4dda9c2)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h := Hash64(p)
		if h != r {
			b.Error(h, "not equal to", r)
		}
	}
}

func BenchmarkFnv64Native(b *testing.B) {
	p := s2b("foobar")
	r := uint64(0x340d8765a4dda9c2)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		f := fnv.New64()
		_, _ = f.Write(p)
		h := f.Sum64()
		if h != r {
			b.Error(h, "not equal to", r)
		}
	}
}

func BenchmarkFnv64a(b *testing.B) {
	p := s2b("foobar")
	r := uint64(0x85944171f73967e8)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h := Hash64a(p)
		if h != r {
			b.Error(h, "not equal to", r)
		}
	}
}

func BenchmarkFnv64aNative(b *testing.B) {
	p := s2b("foobar")
	r := uint64(0x85944171f73967e8)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		f := fnv.New64a()
		_, _ = f.Write(p)
		h := f.Sum64()
		if h != r {
			b.Error(h, "not equal to", r)
		}
	}
}
