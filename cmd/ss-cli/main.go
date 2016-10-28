package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"net"

	"encoding/binary"

	"github.com/zyguan/just"
	"github.com/zyguan/sslite/cipher"
	"github.com/zyguan/sslite/proto"
)

func logErr(err error) error {
	log.Print(err)
	return err
}

func asSocksAddr(addr *net.TCPAddr) []byte {
	ipSize := len(addr.IP)
	buf := make([]byte, ipSize+3)
	buf[0] = byte(proto.ADDR_IPV4)
	if ipSize == 16 {
		buf[0] = byte(proto.ADDR_IPV6)
	}
	copy(buf[1:], addr.IP)
	binary.BigEndian.PutUint16(buf[1+ipSize:], uint16(addr.Port))
	return buf
}

func handle(src net.Conn) {
	defer just.CatchF(logErr)(nil)
	defer src.Close()

	var buf bytes.Buffer

	// handle socks5 greeting
	just.Try(proto.ReadSocksAuthReq(&buf, src))
	just.Try(src.Write([]byte{0x05, 0x00}))

	// read addr from socks5 request
	buf.Reset()
	data := just.Try(proto.ReadSocksConnReq(&buf, src)).([]byte)
	addr := make([]byte, len(data)-3)
	copy(addr, data[3:])

	// connect to shadowsocks server
	cc := cipher.CipherOps{just.Try(cipher.UseCipher(*CONF["method"])).(cipher.Cipher)}
	key := cc.Key(*CONF["password"])
	dst := just.Try(net.Dial("tcp", *CONF["server"])).(net.Conn)
	defer dst.Close()

	// reply to client
	just.Try(src.Write([]byte{0x05, 0x00, 0x00}))
	just.Try(src.Write(asSocksAddr(dst.LocalAddr().(*net.TCPAddr))))

	// pipe src & dst
	errs := make(chan error)
	dumperr := func(err error) error {
		errs <- err
		return nil
	}
	go func() { // src -> dst
		defer just.CatchF(dumperr)(nil)
		dstW := just.Try(cc.Encrypt(dst, key)).(io.Writer)
		just.Try(dstW.Write(addr))
		just.Try(io.Copy(dstW, src))
		errs <- nil
	}()
	go func() { // src <- dst
		defer just.CatchF(dumperr)(nil)
		dstR := just.Try(cc.Decrypt(dst, key)).(io.Reader)
		just.Try(io.Copy(src, dstR))
		errs <- nil
	}()
	just.Try(nil, <-errs)
	just.Try(nil, <-errs)
}

var CONF = make(map[string]*string)

func init() {
	CONF["local"] = flag.String("l", ":1080", "local address")
	CONF["server"] = flag.String("s", "", "server address")
	CONF["method"] = flag.String("m", "aes-256-cfb", "cipher method")
	CONF["password"] = flag.String("p", "", "password")
}

func main() {
	just.CatchF(func(err error) error {
		log.Fatal(err)
		return nil
	})(nil)

	flag.Parse()
	listener := just.Try(net.Listen("tcp", *CONF["local"])).(net.Listener)
	log.Print("ss-cli is serving on ", *CONF["local"])
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print("accept error: ", err)
		}
		go handle(conn)
	}
}
