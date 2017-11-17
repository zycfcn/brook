package brook

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/txthinking/ant"
	"github.com/txthinking/socks5"
)

// IncrementNonce loves your compute to use Litter Endian
func IncrementNonce(n []byte) []byte {
	i := int(binary.LittleEndian.Uint16(n))
	i += 1
	n = make([]byte, 12)
	binary.LittleEndian.PutUint16(n, uint16(i))
	return n
}

// ReadFrom
func ReadFrom(c *net.TCPConn, k, n []byte, hasTime bool) ([]byte, []byte, error) {
	// 第二次接收 请求内容的长度值(下次接收长度的加密值)[加密后的值长度总是18]
	b := make([]byte, 18)
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, nil, err
	}

	// 解密加密值
	n = IncrementNonce(n)
	d, err := ant.AESGCMDecrypt(b, k, n)
	if err != nil {
		return nil, nil, err
	}

	// 约定好的大端序排序 取值
	l := int(binary.BigEndian.Uint16(d))
	b = make([]byte, l)

	// 第三次接收 要请求地址类型,主机和端口
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, nil, err
	}
	// 解密地址类型,主机和端口
	n = IncrementNonce(n)
	d, err = ant.AESGCMDecrypt(b, k, n)
	if err != nil {
		return nil, nil, err
	}

	// 在是代理客户端发过来 CONNECT 方法时有效
	if hasTime {
		i, err := strconv.Atoi(string(d[0:10]))
		if err != nil {
			return nil, nil, err
		}
		// 请求大于 90秒 丢弃
		if time.Now().Unix()-int64(i) > 90 {
			// 为什么需要sleep?
			time.Sleep(time.Duration(ant.Random(1, 60*10)) * time.Second)
			return nil, nil, errors.New("Expired request")
		}
		d = d[10:]
	}
	return d, n, nil
}

// WriteTo
func WriteTo(c *net.TCPConn, d, k, n []byte, needTime bool) ([]byte, error) {
	if needTime {
		//  在是 CONNECT 方法时有效
		d = append(bytes.NewBufferString(strconv.Itoa(int(time.Now().Unix()))).Bytes(), d...)
	}

	i := len(d) + 16
	bb := make([]byte, 2)

	// 大端序 这个概念不太懂的同学可以看下这个链接http://www.ruanyifeng.com/blog/2016/11/byte-order.html
	// 大端序和小端序的不同是一种栈的队序问题,而不是长度大小问题
	// 这里以大端序排序
	binary.BigEndian.PutUint16(bb, uint16(i))

	// 密码的加密手段 小端序
	n = IncrementNonce(n)

	// 把 http 请求的内容长度值 加密
	b, err := ant.AESGCMEncrypt(bb, k, n)
	if err != nil {
		return nil, err
	}

	// 第二次写入 请求内容 长度值(加密后的)
	if _, err := c.Write(b); err != nil {
		return nil, err
	}
	//log.Println("len(b):", len(b))

	// 加密请求内容
	n = IncrementNonce(n)
	b, err = ant.AESGCMEncrypt(d, k, n)
	if err != nil {
		return nil, err
	}
	// 第三次写入 请求内容(请求地址)
	if _, err := c.Write(b); err != nil {
		return nil, err
	}
	return n, nil
}

// PrepareKey
func PrepareKey(p []byte) ([]byte, []byte, error) {
	return ant.HkdfSha256RandomSalt(p, []byte{0x62, 0x72, 0x6f, 0x6f, 0x6b}, 12)
}

// GetKey
func GetKey(p, n []byte) ([]byte, error) {
	return ant.HkdfSha256WithSalt(p, n, []byte{0x62, 0x72, 0x6f, 0x6f, 0x6b})
}

// Encrypt data
func Encrypt(p, b []byte) ([]byte, error) {
	b = append(bytes.NewBufferString(strconv.Itoa(int(time.Now().Unix()))).Bytes(), b...)
	k, n, err := PrepareKey(p)
	if err != nil {
		return nil, err
	}
	b, err = ant.AESGCMEncrypt(b, k, n)
	if err != nil {
		return nil, err
	}
	b = append(n, b...)
	return b, nil
}

// Decrypt data
func Decrypt(p, b []byte) (a byte, addr, port, data []byte, err error) {
	err = errors.New("Data length error")
	if len(b) <= 12+16 {
		return
	}
	k, err := GetKey(p, b[0:12])
	bb, err := ant.AESGCMDecrypt(b[12:], k, b[0:12])
	if err != nil {
		return
	}
	i, err := strconv.Atoi(string(bb[0:10]))
	if err != nil {
		return
	}
	if time.Now().Unix()-int64(i) > 90 {
		time.Sleep(time.Duration(ant.Random(1, 60*10)) * time.Second)
		err = errors.New("Expired request")
		return
	}
	bb = bb[10:]
	a = bb[0]
	if a == socks5.ATYPIPv4 {
		addr = bb[1:5]
		port = bb[5:7]
		data = bb[7:]
	} else if a == socks5.ATYPIPv6 {
		addr = bb[1:17]
		port = bb[17:19]
		data = bb[19:]
	} else if a == socks5.ATYPDomain {
		l := int(bb[1])
		addr = bb[1 : 1+l]
		port = bb[1+l : 1+l+2]
		data = bb[1+l+2:]
	} else {
		return
	}
	err = nil
	return
}
