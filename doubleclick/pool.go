package doubleclick

import "sync"

type Pool struct {
	p sync.Pool
}

var P Pool

// Get DC instance from the pool.
func (p *Pool) Get(typ Type, encryptionKey, integrityKey []byte) *DoubleClick {
	v := p.p.Get()
	if v != nil {
		if x, ok := v.(*DoubleClick); ok {
			x.typ = typ
			x.SetKeys(encryptionKey, integrityKey)
			return x
		}
	}
	x := New(typ, encryptionKey, integrityKey)
	return x
}

// Put instance of DC to the pool.
func (p *Pool) Put(x *DoubleClick) {
	x.Reset()
	p.p.Put(x)
}

// Acquire new DC instance from the default pool.
func Acquire(typ Type, encryptionKey, integrityKey []byte) *DoubleClick {
	return P.Get(typ, encryptionKey, integrityKey)
}

// Release DC instance (put back to default pool).
func Release(x *DoubleClick) {
	P.Put(x)
}
