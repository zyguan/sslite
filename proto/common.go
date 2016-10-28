package proto

import (
	"bytes"
	"io"

	"github.com/zyguan/just"
)

func ReadN(buf *bytes.Buffer, in io.Reader, n int) (_ []byte, err error) {
	defer just.Catch(&err)

	off := buf.Len()
	just.Try(io.CopyN(buf, in, int64(n)))

	return buf.Bytes()[off:], nil
}

func ReadVar(buf *bytes.Buffer, in io.Reader) (_ []byte, err error) {
	defer just.Catch(&err)

	off := buf.Len()
	just.Try(ReadN(buf, in, 1))
	just.Try(ReadN(buf, in, int(buf.Bytes()[off])))

	return buf.Bytes()[off:], nil
}
