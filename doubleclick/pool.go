package doubleclick

import "sync"

type Pool struct {
	p sync.Pool
}

var P Pool

func (p *Pool) Get(encryptionKey, integrityKey []byte) *DoubleClick {
	v := p.p.Get()
	if v != nil {
		if d, ok := v.(*DoubleClick); ok {
			d.SetKeys(encryptionKey, integrityKey)
			return d
		}
	}
	d := New(encryptionKey, integrityKey)
	return d
}

func (p *Pool) Put(d *DoubleClick) {
	d.Reset()
	p.p.Put(d)
}

func Acquire(encryptionKey, integrityKey []byte) *DoubleClick {
	return P.Get(encryptionKey, integrityKey)
}

func Release(b *DoubleClick) {
	P.Put(b)
}
