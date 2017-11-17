package brook

import (
	"io"
	"log"
	"net"
	"time"

	cache "github.com/patrickmn/go-cache"
	"github.com/txthinking/socks5"
)

// Server
type Server struct {
	Password     []byte
	TCPAddr      *net.TCPAddr
	UDPAddr      *net.UDPAddr
	TCPListen    *net.TCPListener
	UDPConn      *net.UDPConn
	UDPExchanges *cache.Cache
	TCPDeadline  int
	TCPTimeout   int
	UDPDeadline  int
}

// NewServer
func NewServer(addr, password string, tcpTimeout, tcpDeadline, udpDeadline int) (*Server, error) {
	taddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	// UDP 协议带有缓存，看这样子是每过下十分钟扫描一个 自己 把已超过60分钟的数据清除
	// 不知道缓存的啥
	cs := cache.New(60*time.Minute, 10*time.Minute)
	s := &Server{
		Password:     []byte(password),
		TCPAddr:      taddr,
		UDPAddr:      uaddr,
		UDPExchanges: cs,
		TCPTimeout:   tcpTimeout,
		TCPDeadline:  tcpDeadline,
		UDPDeadline:  udpDeadline,
	}
	return s, nil
}

// Run server
func (s *Server) ListenAndServe() error {
	errch := make(chan error)
	// 3.1 TCP 协议服务 开一个协程
	go func() {
		errch <- s.RunTCPServer()
	}()

	// 3.2 UDP 协议服务 开一个协程
	go func() {
		errch <- s.RunUDPServer()
	}()

	// 这样是一个协程堵塞调用，任意TCP/UDP服务出错或返回，另一个UDP/TCP go 协程 也会被中断
	return <-errch
}

// RunTCPServer starts tcp server
func (s *Server) RunTCPServer() error {
	var err error
	s.TCPListen, err = net.ListenTCP("tcp", s.TCPAddr)
	if err != nil {
		return err
	}
	defer s.TCPListen.Close()
	for {
		c, err := s.TCPListen.AcceptTCP()
		if err != nil {
			return err
		}
		// 4 每拿到一个客户端连接直接放到 协程 去执行
		go func(c *net.TCPConn) {
			defer c.Close()
			if s.TCPTimeout != 0 {
				// 关于 SetKeepAlivePeriod 只需关心它是设置 保持TCP长连接的活动时间 （以秒为单位）
				// 详情请看(http://www.oschina.net/translate/tcp-keepalive-with-golang)
				if err := c.SetKeepAlivePeriod(time.Duration(s.TCPTimeout) * time.Second); err != nil {
					log.Println(err)
					return
				}
			}
			if s.TCPDeadline != 0 {
				// 设置对客户端的读、写超时时间
				if err := c.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); err != nil {
					log.Println(err)
					return
				}
			}

			// 5 开始处理客户端请求
			if err := s.TCPHandle(c); err != nil {
				log.Println(err)
			}
		}(c)
	}
	return nil
}

// RunUDPServer starts udp server
func (s *Server) RunUDPServer() error {
	var err error
	s.UDPConn, err = net.ListenUDP("udp", s.UDPAddr)
	if err != nil {
		return err
	}
	defer s.UDPConn.Close()
	for {
		b := make([]byte, 65536)
		n, addr, err := s.UDPConn.ReadFromUDP(b)
		if err != nil {
			return err
		}
		go func(addr *net.UDPAddr, b []byte) {
			if err := s.UDPHandle(addr, b); err != nil {
				log.Println(err)
				return
			}
		}(addr, b[0:n])
	}
	return nil
}

// TCPHandle handle request
func (s *Server) TCPHandle(c *net.TCPConn) error {
	// 该 12 长度字节是和客户端约定好的，加密后的密码长度
	cn := make([]byte, 12)
	// io.ReadFull 官方包解释的很清楚了，因为不常用，这里再啰嗦一遍
	// 从 c 里面读取 cn 长度的字节，并放到cn
	// 如果 c 可读字节为0 .返回 EOF 异常错误
	// 如果 c 可读字节数小于 cn 长度， 返回 ErrUnexpectedEOF 异常错误
	// 只有在 err == nil 时， 返回的第一个字节为实际读取字节数
	// 本用法： 客户端向服务端请求连接后，首先会发送加密后的密码（长度12）
	// 这里服务端会首先读取密码
	// 第一次接收 密码
	if _, err := io.ReadFull(c, cn); err != nil {
		return err
	}
	// 解密 PrepareKey(p []byte) (k []byte, []byte, error) 返回的 k
	ck, err := GetKey(s.Password, cn)
	if err != nil {
		return err
	}
	var b []byte
	// 返回解密后的 b : 地址类型 、 主机名/IP 和 端口号
	b, cn, err = ReadFrom(c, ck, cn, true)
	if err != nil {
		return err
	}
	address := socks5.ToAddress(b[0], b[1:len(b)-2], b[len(b)-2:])
	tmp, err := Dial.Dial("tcp", address)
	if err != nil {
		return err
	}
	rc := tmp.(*net.TCPConn)
	defer rc.Close()
	if s.TCPTimeout != 0 {
		if err := rc.SetKeepAlivePeriod(time.Duration(s.TCPTimeout) * time.Second); err != nil {
			return err
		}
	}
	if s.TCPDeadline != 0 {
		if err := rc.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); err != nil {
			return err
		}
	}

	// 异步处理代理客户端到本代理服务端的请求和代理服务端到代理用户请求的目的地请求
	go func() {
		k, n, err := PrepareKey(s.Password)
		if err != nil {
			log.Println(err)
			return
		}
		if _, err := c.Write(n); err != nil {
			return
		}
		var b [1024 * 2]byte
		for {
			if s.TCPDeadline != 0 {
				if err := rc.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); err != nil {
					return
				}
			}
			i, err := rc.Read(b[:])
			if err != nil {
				return
			}
			n, err = WriteTo(c, b[0:i], k, n, false)
			if err != nil {
				return
			}
		}
	}()

	for {
		if s.TCPDeadline != 0 {
			if err := c.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); err != nil {
				return nil
			}
		}
		// 首先进行 第四次 读取，接下来进行第n .....次读取
		b, cn, err = ReadFrom(c, ck, cn, false)
		if err != nil {
			return nil
		}
		if _, err := rc.Write(b); err != nil {
			return nil
		}
	}
	return nil
}

// UDPHandle handle packet
func (s *Server) UDPHandle(addr *net.UDPAddr, b []byte) error {
	a, h, p, data, err := Decrypt(s.Password, b)
	if err != nil {
		return err
	}
	send := func(ue *socks5.UDPExchange, data []byte) error {
		_, err := ue.RemoteConn.Write(data)
		if err != nil {
			return err
		}
		return nil
	}

	var ue *socks5.UDPExchange
	iue, ok := s.UDPExchanges.Get(addr.String())
	if ok {
		ue = iue.(*socks5.UDPExchange)
		return send(ue, data)
	}
	address := socks5.ToAddress(a, h, p)

	c, err := Dial.Dial("udp", address)
	if err != nil {
		return err
	}
	rc := c.(*net.UDPConn)
	ue = &socks5.UDPExchange{
		ClientAddr: addr,
		RemoteConn: rc,
	}
	s.UDPExchanges.Set(ue.ClientAddr.String(), ue, cache.DefaultExpiration)
	if err := send(ue, data); err != nil {
		return err
	}
	go func(ue *socks5.UDPExchange) {
		defer func() {
			s.UDPExchanges.Delete(ue.ClientAddr.String())
			ue.RemoteConn.Close()
		}()
		var b [65536]byte
		for {
			if s.UDPDeadline != 0 {
				if err := ue.RemoteConn.SetDeadline(time.Now().Add(time.Duration(s.UDPDeadline) * time.Second)); err != nil {
					break
				}
			}
			n, err := ue.RemoteConn.Read(b[:])
			if err != nil {
				break
			}
			a, addr, port, err := socks5.ParseAddress(ue.ClientAddr.String())
			if err != nil {
				log.Println(err)
				break
			}
			d := make([]byte, 0, 7)
			d = append(d, a)
			d = append(d, addr...)
			d = append(d, port...)
			d = append(d, b[0:n]...)
			cd, err := Encrypt(s.Password, d)
			if err != nil {
				log.Println(err)
				break
			}
			if _, err := s.UDPConn.WriteToUDP(cd, ue.ClientAddr); err != nil {
				break
			}
		}
	}(ue)
	return nil
}

// Shutdown server
func (s *Server) Shutdown() error {
	var err, err1 error
	if s.TCPListen != nil {
		err = s.TCPListen.Close()
	}
	if s.UDPConn != nil {
		err1 = s.UDPConn.Close()
	}
	if err != nil {
		return err
	}
	return err1
}
