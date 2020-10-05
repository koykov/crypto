package doubleclick

import "sync"

type Pool struct {
	p sync.Pool
}

var P Pool

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

func (p *Pool) Put(x *DoubleClick) {
	x.Reset()
	p.p.Put(x)
}

func Acquire(typ Type, encryptionKey, integrityKey []byte) *DoubleClick {
	return P.Get(typ, encryptionKey, integrityKey)
}

func Release(x *DoubleClick) {
	P.Put(x)
}
