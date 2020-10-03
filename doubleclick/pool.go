package doubleclick

import "sync"

type Pool struct {
	adid, idfa, price sync.Pool
}

var P Pool

func (p *Pool) GetAdID(encryptionKey, integrityKey []byte) *AdID {
	v := p.adid.Get()
	if v != nil {
		if a, ok := v.(*AdID); ok {
			a.SetKeys(encryptionKey, integrityKey)
			return a
		}
	}
	a := NewAdID(encryptionKey, integrityKey)
	return a
}

func (p *Pool) PutAdID(a *AdID) {
	a.Reset()
	p.adid.Put(a)
}

func AcquireAdID(encryptionKey, integrityKey []byte) *AdID {
	return P.GetAdID(encryptionKey, integrityKey)
}

func ReleaseAdID(a *AdID) {
	P.PutAdID(a)
}
