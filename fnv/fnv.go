package fnv

import (
	"reflect"
	"unsafe"
)

// Collection of loop-rolled calculation of FNV hashes.
// Note than loop-rolling is faster than simple loop only on long string (64+ symbols).

const (
	offset32 = uint32(2166136261)
	offset64 = uint64(14695981039346656037)
	prime32  = uint32(16777619)
	prime64  = uint64(1099511628211)
)

var (
	_ = Hash32String
	_ = Hash32StringLong
	_ = Hash32aString
	_ = Hash32aStringLong
	_ = Hash64String
	_ = Hash64StringLong
	_ = Hash64aString
	_ = Hash64aStringLong
)

// Fast FNV-1 32 hash calculation.
func Hash32(p []byte) uint32 {
	h := offset32
	for _, c := range p {
		h *= prime32
		h ^= uint32(c)
	}
	return h
}

// Loop rolled version of FNV-1 32 for very long input.
func Hash32Long(p []byte) uint32 {
	h := offset32

	for len(p) >= 8 {
		h *= prime32
		h ^= uint32(p[0])
		h *= prime32
		h ^= uint32(p[1])
		h *= prime32
		h ^= uint32(p[2])
		h *= prime32
		h ^= uint32(p[3])
		h *= prime32
		h ^= uint32(p[4])
		h *= prime32
		h ^= uint32(p[5])
		h *= prime32
		h ^= uint32(p[6])
		h *= prime32
		h ^= uint32(p[7])
		p = p[8:]
	}

	if len(p) >= 4 {
		h *= prime32
		h ^= uint32(p[0])
		h *= prime32
		h ^= uint32(p[1])
		h *= prime32
		h ^= uint32(p[2])
		h *= prime32
		h ^= uint32(p[3])
		p = p[4:]
	}

	if len(p) >= 2 {
		h *= prime32
		h ^= uint32(p[0])
		h *= prime32
		h ^= uint32(p[1])
		p = p[2:]
	}

	if len(p) > 0 {
		h *= prime32
		h ^= uint32(p[0])
	}

	return h
}

// Fast FNV-1 32 hash calculation of string.
func Hash32String(s string) uint32 {
	return Hash32(s2b(s))
}

// Loop rolled version of FNV-1 32 for very long strings.
func Hash32StringLong(s string) uint32 {
	return Hash32Long(s2b(s))
}

// Fast FNV-1a 32 hash calculation.
func Hash32a(p []byte) uint32 {
	h := offset32
	for _, c := range p {
		h = (h ^ uint32(c)) * prime32
	}
	return h
}

// Loop rolled version of FNV-1a 32 for very long input.
func Hash32aLong(p []byte) uint32 {
	h := offset32

	for len(p) >= 8 {
		h = (h ^ uint32(p[0])) * prime32
		h = (h ^ uint32(p[1])) * prime32
		h = (h ^ uint32(p[2])) * prime32
		h = (h ^ uint32(p[3])) * prime32
		h = (h ^ uint32(p[4])) * prime32
		h = (h ^ uint32(p[5])) * prime32
		h = (h ^ uint32(p[6])) * prime32
		h = (h ^ uint32(p[7])) * prime32
		p = p[8:]
	}

	if len(p) >= 4 {
		h = (h ^ uint32(p[0])) * prime32
		h = (h ^ uint32(p[1])) * prime32
		h = (h ^ uint32(p[2])) * prime32
		h = (h ^ uint32(p[3])) * prime32
		p = p[4:]
	}

	if len(p) >= 2 {
		h = (h ^ uint32(p[0])) * prime32
		h = (h ^ uint32(p[1])) * prime32
		p = p[2:]
	}

	if len(p) > 0 {
		h = (h ^ uint32(p[0])) * prime32
	}

	return h
}

// Fast FNV-1a 32 hash calculation of string.
func Hash32aString(s string) uint32 {
	return Hash32a(s2b(s))
}

// Loop rolled FNV-1a 32 for very long strings.
func Hash32aStringLong(s string) uint32 {
	return Hash32aLong(s2b(s))
}

// Fast FNV-1 64 hash calculation.
func Hash64(p []byte) uint64 {
	h := offset64
	for _, c := range p {
		h *= prime64
		h ^= uint64(c)
	}
	return h
}

// Loop rolled version of FNV-1 64 for very long input.
func Hash64Long(p []byte) uint64 {
	h := offset64

	for len(p) >= 8 {
		h *= prime64
		h ^= uint64(p[0])
		h *= prime64
		h ^= uint64(p[1])
		h *= prime64
		h ^= uint64(p[2])
		h *= prime64
		h ^= uint64(p[3])
		h *= prime64
		h ^= uint64(p[4])
		h *= prime64
		h ^= uint64(p[5])
		h *= prime64
		h ^= uint64(p[6])
		h *= prime64
		h ^= uint64(p[7])
		p = p[8:]
	}

	if len(p) >= 4 {
		h *= prime64
		h ^= uint64(p[0])
		h *= prime64
		h ^= uint64(p[1])
		h *= prime64
		h ^= uint64(p[2])
		h *= prime64
		h ^= uint64(p[3])
		p = p[4:]
	}

	if len(p) >= 2 {
		h *= prime64
		h ^= uint64(p[0])
		h *= prime64
		h ^= uint64(p[1])
		p = p[2:]
	}

	if len(p) > 0 {
		h *= prime64
		h ^= uint64(p[0])
	}

	return h
}

// Fast FNV-1 64 hash calculation of string.
func Hash64String(s string) uint64 {
	return Hash64(s2b(s))
}

// Loop rolled version of FNV-1 64 for very long strings.
func Hash64StringLong(s string) uint64 {
	return Hash64Long(s2b(s))
}

// Fast FNV-1a 64 hash calculation.
func Hash64a(p []byte) uint64 {
	h := offset64
	for _, c := range p {
		h = (h ^ uint64(c)) * prime64
	}
	return h
}

// Loop rolled version of FNV-1a 64 for very long input.
func Hash64aLong(p []byte) uint64 {
	h := offset64

	for len(p) >= 8 {
		h = (h ^ uint64(p[0])) * prime64
		h = (h ^ uint64(p[1])) * prime64
		h = (h ^ uint64(p[2])) * prime64
		h = (h ^ uint64(p[3])) * prime64
		h = (h ^ uint64(p[4])) * prime64
		h = (h ^ uint64(p[5])) * prime64
		h = (h ^ uint64(p[6])) * prime64
		h = (h ^ uint64(p[7])) * prime64
		p = p[8:]
	}

	if len(p) >= 4 {
		h = (h ^ uint64(p[0])) * prime64
		h = (h ^ uint64(p[1])) * prime64
		h = (h ^ uint64(p[2])) * prime64
		h = (h ^ uint64(p[3])) * prime64
		p = p[4:]
	}

	if len(p) >= 2 {
		h = (h ^ uint64(p[0])) * prime64
		h = (h ^ uint64(p[1])) * prime64
		p = p[2:]
	}

	if len(p) > 0 {
		h = (h ^ uint64(p[0])) * prime64
	}

	return h
}

// Fast FNV-1a 64 hash calculation of string.
func Hash64aString(s string) uint64 {
	return Hash64a(s2b(s))
}

// Loop rolled version of FNV-1a 64 for very long strings.
func Hash64aStringLong(s string) uint64 {
	return Hash64aLong(s2b(s))
}

// Fast and alloc-free conversion of string to byte sequence.
func s2b(s string) []byte {
	strh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	var sh reflect.SliceHeader
	sh.Data = strh.Data
	sh.Len = strh.Len
	sh.Cap = strh.Len
	return *(*[]byte)(unsafe.Pointer(&sh))
}
