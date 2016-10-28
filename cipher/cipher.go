package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"errors"
)

func UseCipher(name string) (Cipher, error) {
	if c, ok := registeredCipher[name]; ok {
		return c, nil
	}
	return nil, errors.New("Unsupported encryption method: " + name)
}

func Ciphers() []string {
	ns := make([]string, 0, len(registeredCipher))
	for n, _ := range registeredCipher {
		ns = append(ns, n)
	}
	return ns
}

func Rigister(name string, cipher Cipher) {
	registeredCipher[name] = cipher
}

type CipherFn func(key, iv []byte) (cipher.Stream, error)

func ComposeCipherFn(
	B func([]byte) (cipher.Block, error),
	S func(cipher.Block, []byte) cipher.Stream,
) CipherFn {
	return func(key, iv []byte) (cipher.Stream, error) {
		b, err := B(key)
		if err != nil {
			return nil, err
		}
		return S(b, iv), nil
	}
}

type Cipher interface {
	KeySize() int
	IVSize() int
	Decryptor([]byte, []byte) (cipher.Stream, error)
	Encryptor([]byte, []byte) (cipher.Stream, error)
}

func NewCFBCipher(keySize int, ivSize int, B func([]byte) (cipher.Block, error)) Cipher {
	dec := ComposeCipherFn(B, cipher.NewCFBDecrypter)
	enc := ComposeCipherFn(B, cipher.NewCFBEncrypter)
	return &cc{keySize, ivSize, dec, enc}
}

var registeredCipher map[string]Cipher

type cc struct {
	keySize  int
	ivSize   int
	dec, enc CipherFn
}

func (c *cc) KeySize() int {
	return c.keySize
}

func (c *cc) IVSize() int {
	return c.ivSize
}

func (c *cc) Decryptor(key, iv []byte) (cipher.Stream, error) {
	return c.dec(key, iv)
}

func (c *cc) Encryptor(key, iv []byte) (cipher.Stream, error) {
	return c.enc(key, iv)
}

func init() {
	rc4md5Fn := func(key, iv []byte) (cipher.Stream, error) {
		h := md5.New()
		h.Write(key)
		h.Write(iv)
		return rc4.NewCipher(h.Sum(nil))
	}
	registeredCipher = map[string]Cipher{
		"aes-128-cfb": NewCFBCipher(16, 16, aes.NewCipher),
		"aes-192-cfb": NewCFBCipher(24, 16, aes.NewCipher),
		"aes-256-cfb": NewCFBCipher(32, 16, aes.NewCipher),
		"des-cfb":     NewCFBCipher(8, 8, des.NewCipher),
		"rc4-md5":     &cc{16, 16, rc4md5Fn, rc4md5Fn},
	}
}
