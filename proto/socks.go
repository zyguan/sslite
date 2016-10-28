package proto

import (
	"bytes"
	"fmt"
	"io"

	"github.com/zyguan/just"
)

type ATYP uint8

const (
	ADDR_IPV4 ATYP = 1
	ADDR_IPV6 ATYP = 4
	ADDR_FQDN ATYP = 3
)

func ReadSocksAddr(buf *bytes.Buffer, in io.Reader) (_ []byte, err error) {
	defer just.Catch(&err)

	off := buf.Len()
	// ATYP
	atyp := just.Try(ReadN(buf, in, 1)).([]byte)
	// ADDR
	switch ATYP(atyp[0] & 0x0f) {
	case ADDR_IPV4:
		just.Try(ReadN(buf, in, 4))
	case ADDR_IPV6:
		just.Try(ReadN(buf, in, 16))
	case ADDR_FQDN:
		just.Try(ReadVar(buf, in))
	default:
		return nil, fmt.Errorf("Unknown address type: 0x%x", atyp[0])
	}
	// PORT
	just.Try(ReadN(buf, in, 2))

	return buf.Bytes()[off:], nil
}

func ReadSocksAuthReq(buf *bytes.Buffer, in io.Reader) (_ []byte, err error) {
	defer just.Catch(&err)

	off := buf.Len()
	// VER
	ver := just.Try(ReadN(buf, in, 1)).([]byte)
	if ver[0] != 0x05 {
		return nil, fmt.Errorf("Unsupported socks version: 0x%x", ver[0])
	}
	// METHODS
	ms := just.Try(ReadVar(buf, in)).([]byte)
	auth := true
	for i := 1; i < len(ms); i++ {
		if ms[i] == 0x00 {
			auth = false
			break
		}
	}
	if auth {
		return nil, fmt.Errorf("Wanted NOAUTH but not found")
	}

	return buf.Bytes()[off:], nil
}

func ReadSocksConnReq(buf *bytes.Buffer, in io.Reader) (_ []byte, err error) {
	defer just.Catch(&err)

	off := buf.Len()
	// VER:CMD:RSV
	vcr := just.Try(ReadN(buf, in, 3)).([]byte)
	if vcr[0] != 0x05 {
		return nil, fmt.Errorf("Unsupported socks version: 0x%x", vcr[0])
	}
	if vcr[1] != 0x01 {
		return nil, fmt.Errorf("Unsupported socks command: 0x%x", vcr[1])
	}
	// ADDR
	just.Try(ReadSocksAddr(buf, in))

	return buf.Bytes()[off:], nil
}
