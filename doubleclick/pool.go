package doubleclick

import "sync"

type Pool struct {
	adid, idfa, price sync.Pool
}

var P Pool

func (p *Pool) GetAdID(encryptionKey, integrityKey []byte) *AdID {
	v := p.adid.Get()
	if v != nil {
		if x, ok := v.(*AdID); ok {
			x.SetKeys(encryptionKey, integrityKey)
			return x
		}
	}
	x := NewAdID(encryptionKey, integrityKey)
	return x
}

func (p *Pool) PutAdID(x *AdID) {
	x.Reset()
	p.adid.Put(x)
}

func AcquireAdID(encryptionKey, integrityKey []byte) *AdID {
	return P.GetAdID(encryptionKey, integrityKey)
}

func ReleaseAdID(x *AdID) {
	P.PutAdID(x)
}

func (p *Pool) GetIdfa(encryptionKey, integrityKey []byte) *Idfa {
	v := p.idfa.Get()
	if v != nil {
		if x, ok := v.(*Idfa); ok {
			x.SetKeys(encryptionKey, integrityKey)
			return x
		}
	}
	x := NewIdfa(encryptionKey, integrityKey)
	return x
}

func (p *Pool) PutIdfa(x *Idfa) {
	x.Reset()
	p.idfa.Put(x)
}

func AcquireIdfa(encryptionKey, integrityKey []byte) *Idfa {
	return P.GetIdfa(encryptionKey, integrityKey)
}

func ReleaseIdfa(x *Idfa) {
	P.PutIdfa(x)
}
