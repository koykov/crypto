# DoubleClick

An encryption/decryption support of DoubleClick Ad Exchange RTB protocol messages.
Currently, supports four types of messages:
* Advertising ID ([AdID](https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-advertising-id))
* ID for Advertisers ([IDFA](https://support.google.com/authorizedbuyers/answer/3221407))
* Hyperlocal Targeting Signals ([Hyperlocal](https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-hyperlocal))
* Price Confirmations ([Price](https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-price))

## Usage

Encryption:
```go
var (
    encryptionKey = []byte("...") // from config, len 32 bytes
    integrityKey  = []byte("...") // from config, len 32 bytes
    initVec = []byte("...") // from config, len 16 bytes
    dst []byte
    err error
)

plainID := []byte("0123456789abcdef")
dc := doubleclick.New(doubleclick.TypeAdID, encryptionKey, integrityKey)
dst, err = dc.Encrypt(dst, initVec, plainID)
assertEqual(err, nil)
assertTrue(bytes.Equal(dst, []byte("..."))) // 32 bytes len encrypted ID
```

Descryption:
```go
var (
    encryptionKey = []byte("...") // from config, len 32 bytes
    integrityKey  = []byte("...") // from config, len 32 bytes
    dst []byte
    err error
)

cipherID := []byte("...") // 32 bytes len encrypted ID
dc := doubleclick.New(doubleclick.TypeAdID, encryptionKey, integrityKey)
dst, err = dc.Decrypt(dst, cipherID)
assertEqual(err, nil)
assertTrue(bytes.Equal(dst, []byte("0123456789abcdef")))
```

## Performance tips

Use pool instead of direct call `doubleclick.New` method. Example of usage:
```go
var p doubleclick.Pool

dc := p.Get(doubleclick.TypeAdID, encryptionKey, integrityKey)
// ...
p.Put(dc)
```

DC has builtin pool, you may use it shorter by call functions `Acquire`/`Release`. Example:
```go
dc := doubleclick.Acquire(doubleclick.TypeAdID, encryptionKey, integrityKey)
// ...
doubleclick.Release(dc)
```
