package cipher

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"
	"net"
)

type CipherOps struct {
	Cipher
}

func (c *CipherOps) Key(password string) []byte {
	const md5Len = 16
	md5sum := func(d []byte) []byte {
		h := md5.New()
		h.Write(d)
		return h.Sum(nil)
	}

	cnt := (c.KeySize()-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, md5sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], md5sum(d))
	}
	return m[:c.KeySize()]
}

func (c *CipherOps) ReadIVFrom(r io.Reader) ([]byte, error) {
	iv := make([]byte, c.IVSize())
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

func (c *CipherOps) DecryptReader(r io.Reader, key []byte, iv []byte) (io.Reader, error) {
	if err := validateSizes(c, key, iv); err != nil {
		return nil, err
	}
	dec, err := c.Decryptor(key, iv)
	if err != nil {
		return nil, err
	}
	return &cipher.StreamReader{R: r, S: dec}, nil
}

func (c *CipherOps) EncryptWriter(w io.Writer, key []byte, iv []byte) (io.Writer, error) {
	if err := validateSizes(c, key, iv); err != nil {
		return nil, err
	}
	enc, err := c.Encryptor(key, iv)
	if err != nil {
		return nil, err
	}
	return &cipher.StreamWriter{W: w, S: enc}, nil
}

func (c *CipherOps) Decrypt(conn net.Conn, key []byte) (io.Reader, error) {
	iv, err := c.ReadIVFrom(conn)
	if err != nil {
		return nil, err
	}
	return c.DecryptReader(conn, key, iv)
}

func (c *CipherOps) Encrypt(conn net.Conn, key []byte) (io.Writer, error) {
	iv, err := c.ReadIVFrom(rand.Reader)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(iv); err != nil {
		return nil, err
	}
	return c.EncryptWriter(conn, key, iv)
}

func OTAHash(key []byte, data []byte) []byte {
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(data)
	return hmacSha1.Sum(nil)[:10]
}

func validateSizes(c Cipher, key []byte, iv []byte) error {
	if c.KeySize() != len(key) {
		return fmt.Errorf("Invalid key size: %d (expect %d)", len(key), c.KeySize())
	}
	if c.IVSize() != len(iv) {
		return fmt.Errorf("Invalid iv size: %d (expect %d)", len(iv), c.IVSize())
	}
	return nil
}
