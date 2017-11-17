package brook

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"time"

	cache "github.com/patrickmn/go-cache"
	"github.com/txthinking/ant"
	"github.com/txthinking/socks5"
)

// Client
type Client struct {
	Server          *socks5.Server
	RemoteAddr      string
	Password        []byte
	TCPTimeout      int
	TCPDeadline     int
	UDPDeadline     int
	Socks5Middleman Socks5Middleman
	HTTPMiddleman   HTTPMiddleman
	TCPListen       *net.TCPListener
}

// NewClient returns a new Client
func NewClient(addr, ip, server, password string, tcpTimeout, tcpDeadline, udpDeadline, udpSessionTime int) (*Client, error) {
	// 4 很重要的一个方法: 它会返回一个本地服务对象
	// 该s5 服务绑定本地的TCP 和 UDP 协议端口，IP and prot 是命令行的listen -l
	// 同时会绑定 ip 参数的地址 和 listen 端口的组合的 UDP 协议端口 ，不知道干啥
	s5, err := socks5.NewClassicServer(addr, ip, "", "", tcpTimeout, tcpDeadline, udpDeadline, udpSessionTime)
	if err != nil {
		return nil, err
	}
	x := &Client{
		RemoteAddr:  server,
		Server:      s5,
		Password:    []byte(password),
		TCPTimeout:  tcpTimeout,
		TCPDeadline: tcpDeadline,
		UDPDeadline: udpDeadline,
	}
	return x, nil
}

// ListenAndServe will let client start a socks5 proxy
// sm can be nil
func (x *Client) ListenAndServe(sm Socks5Middleman) error {
	x.Socks5Middleman = sm
	return x.Server.Run(x)
}

// TCPHandle handles tcp request
func (x *Client) TCPHandle(s *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if x.Socks5Middleman != nil {
		done, err := x.Socks5Middleman.TCPHandle(s, c, r)
		if err != nil {
			if done {
				return err
			}
			return ErrorReply(r, c, err)
		}
		if done {
			return nil
		}
	}

	if r.Cmd == socks5.CmdConnect {
		tmp, err := Dial.Dial("tcp", x.RemoteAddr)
		if err != nil {
			return ErrorReply(r, c, err)
		}
		rc := tmp.(*net.TCPConn)
		defer rc.Close()
		if x.TCPTimeout != 0 {
			if err := rc.SetKeepAlivePeriod(time.Duration(x.TCPTimeout) * time.Second); err != nil {
				return ErrorReply(r, c, err)
			}
		}
		if x.TCPDeadline != 0 {
			if err := rc.SetDeadline(time.Now().Add(time.Duration(x.TCPDeadline) * time.Second)); err != nil {
				return ErrorReply(r, c, err)
			}
		}

		k, n, err := PrepareKey(x.Password)
		if err != nil {
			return ErrorReply(r, c, err)
		}
		if _, err := rc.Write(n); err != nil {
			return ErrorReply(r, c, err)
		}

		rawaddr := make([]byte, 0, 7)
		rawaddr = append(rawaddr, r.Atyp)
		rawaddr = append(rawaddr, r.DstAddr...)
		rawaddr = append(rawaddr, r.DstPort...)
		n, err = WriteTo(rc, rawaddr, k, n, true)
		if err != nil {
			return ErrorReply(r, c, err)
		}

		a, address, port, err := socks5.ParseAddress(rc.LocalAddr().String())
		if err != nil {
			return ErrorReply(r, c, err)
		}
		rp := socks5.NewReply(socks5.RepSuccess, a, address, port)
		if err := rp.WriteTo(c); err != nil {
			return err
		}

		go func() {
			n := make([]byte, 12)
			if _, err := io.ReadFull(rc, n); err != nil {
				return
			}
			k, err := GetKey(x.Password, n)
			if err != nil {
				log.Println(err)
				return
			}
			var b []byte
			for {
				if x.TCPDeadline != 0 {
					if err := rc.SetDeadline(time.Now().Add(time.Duration(x.TCPDeadline) * time.Second)); err != nil {
						return
					}
				}
				b, n, err = ReadFrom(rc, k, n, false)
				if err != nil {
					return
				}
				if _, err := c.Write(b); err != nil {
					return
				}
			}
		}()

		var b [1024 * 2]byte
		for {
			if x.TCPDeadline != 0 {
				if err := c.SetDeadline(time.Now().Add(time.Duration(x.TCPDeadline) * time.Second)); err != nil {
					return nil
				}
			}
			i, err := c.Read(b[:])
			if err != nil {
				return nil
			}
			n, err = WriteTo(rc, b[0:i], k, n, false)
			if err != nil {
				return nil
			}
		}
		return nil
	}
	if r.Cmd == socks5.CmdUDP {
		caddr, err := r.UDP(c, x.Server.ServerAddr)
		if err != nil {
			return err
		}
		_, p, err := net.SplitHostPort(caddr.String())
		if err != nil {
			return err
		}
		if p == "0" {
			time.Sleep(time.Duration(x.Server.UDPSessionTime) * time.Second)
			return nil
		}
		ch := make(chan byte)
		x.Server.TCPUDPAssociate.Set(caddr.String(), ch, cache.DefaultExpiration)
		<-ch
		return nil
	}
	return socks5.ErrUnsupportCmd
}

// UDPHandle handles udp request
func (x *Client) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	if x.Socks5Middleman != nil {
		if done, err := x.Socks5Middleman.UDPHandle(s, addr, d); err != nil || done {
			return err
		}
	}

	send := func(ue *socks5.UDPExchange, data []byte) error {
		cd, err := Encrypt(x.Password, data)
		if err != nil {
			return err
		}
		_, err = ue.RemoteConn.Write(cd)
		if err != nil {
			return err
		}
		return nil
	}

	var ue *socks5.UDPExchange
	iue, ok := s.UDPExchanges.Get(addr.String())
	if ok {
		ue = iue.(*socks5.UDPExchange)
		return send(ue, d.Bytes()[3:])
	}

	c, err := Dial.Dial("udp", x.RemoteAddr)
	if err != nil {
		return err
	}
	rc := c.(*net.UDPConn)
	ue = &socks5.UDPExchange{
		ClientAddr: addr,
		RemoteConn: rc,
	}
	if err := send(ue, d.Bytes()[3:]); err != nil {
		return err
	}
	s.UDPExchanges.Set(ue.ClientAddr.String(), ue, cache.DefaultExpiration)
	go func(ue *socks5.UDPExchange) {
		defer func() {
			v, ok := s.TCPUDPAssociate.Get(ue.ClientAddr.String())
			if ok {
				ch := v.(chan byte)
				ch <- '0'
			}
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
			_, _, _, data, err := Decrypt(x.Password, b[0:n])
			if err != nil {
				log.Println(err)
				break
			}
			a, addr, port, err := socks5.ParseAddress(ue.ClientAddr.String())
			if err != nil {
				log.Println(err)
				break
			}
			d1 := socks5.NewDatagram(a, addr, port, data)
			if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
				break
			}
		}
	}(ue)
	return nil
}

// ListenAndServeHTTP will let client start a http proxy
// m can be nil
func (x *Client) ListenAndServeHTTP(m HTTPMiddleman) error {
	var err error
	x.HTTPMiddleman = m
	// 该 x.Server 为本地绑定 服务 （即命令行 listen -l 参数值绑定的端口）
	x.TCPListen, err = net.ListenTCP("tcp", x.Server.TCPAddr)
	if err != nil {
		return nil
	}
	for {
		c, err := x.TCPListen.AcceptTCP()
		if err != nil {
			return err
		}
		// 4 每拿到一个代理用户的请求直接放到 协程 去执行
		go func(c *net.TCPConn) {
			defer c.Close()
			if x.TCPTimeout != 0 {
				// 设置 tcp 保持的活动时间
				if err := c.SetKeepAlivePeriod(time.Duration(x.TCPTimeout) * time.Second); err != nil {
					log.Println(err)
					return
				}
			}
			if x.TCPDeadline != 0 {
				// 设置对代理用户的读、写超时时间
				if err := c.SetDeadline(time.Now().Add(time.Duration(x.TCPDeadline) * time.Second)); err != nil {
					log.Println(err)
					return
				}
			}

			// 5 开始处理请求
			if err := x.HTTPHandle(c); err != nil {
				log.Println(err)
				return
			}
		}(c)
	}
}

// c *net.TCPConn 为代理用户（浏览器或系统等）
// HTTPHandle handle http request
func (x *Client) HTTPHandle(c *net.TCPConn) error {
	// 5.1 日志每收到一次请求就打印一次
	log.Println("Got http connection")
	// 存放一次请求的 http header
	b := make([]byte, 0, 1024)

	// 循环接收 代理用户 发达的一次请求的字节每次1024字节
	// 代理中的请求头部类型这样:
	//  CONNECT www.web-tinker.com:80 HTTP/1.1
	//
	//  Host: www.web-tinker.com:80
	//
	//  Proxy-Connection: Keep-Alive
	//
	//  Proxy-Authorization: Basic *
	//
	//  Content-Length: 0
	for {
		var b1 [1024]byte
		n, err := c.Read(b1[:])
		if err != nil {
			return err
		}
		b = append(b, b1[:n]...)
		// 判断 是否读到 http header 结尾符
		if bytes.Contains(b, []byte{0x0d, 0x0a, 0x0d, 0x0a}) {
			break
		}
		// 能处理的 http header 最大字节数 2083+18
		if len(b) >= 2083+18 {
			return errors.New("HTTP header too long")
		}
	}
	bb := bytes.SplitN(b, []byte(" "), 3)
	if len(bb) != 3 {
		return errors.New("Invalid Request")
	}
	method, aoru := string(bb[0]), string(bb[1])
	var addr string
	// HTTP 代理请求方法为 CONNECT
	if method == "CONNECT" {
		addr = aoru
	}
	if method != "CONNECT" {
		var err error
		// 如果请求过来的不是 CONNECT 方法，就从请求头的 HOST key 读取主机信息
		// GetAddressFromURL 这个方法; 返回主机名(IP):端口号
		// 如果aoru 没有端口号会当作IPV6 的方式格式返回 [主机名(IP)]:端口号
		addr, err = ant.GetAddressFromURL(aoru)
		if err != nil {
			return err
		}
	}

	// 这个没搞明白
	if x.HTTPMiddleman != nil {
		if done, err := x.HTTPMiddleman.Handle(method, addr, b, c); err != nil || done {
			return err
		}
	}

	// 拨号 和远程服务端建立 TCP 连接
	// 这里要说明一下，作者用了一个 GOLANG 的接口继承
	// 其实 调用了 net 包的 DialTimeout 方法 timeout 为 10秒
	tmp, err := Dial.Dial("tcp", x.RemoteAddr)
	if err != nil {
		return err
	}
	rc := tmp.(*net.TCPConn)
	defer rc.Close()
	if x.TCPTimeout != 0 {
		if err := rc.SetKeepAlivePeriod(time.Duration(x.TCPTimeout) * time.Second); err != nil {
			return err
		}
	}
	if x.TCPDeadline != 0 {
		if err := rc.SetDeadline(time.Now().Add(time.Duration(x.TCPDeadline) * time.Second)); err != nil {
			return err
		}
	}

	k, n, err := PrepareKey(x.Password)
	if err != nil {
		return err
	}
	// 第一次写入 密码
	if _, err := rc.Write(n); err != nil {
		return err
	}

	// h, p 好说一看就是主机 和 端口,
	// a 为 h 的 IP 类型
	// 下面为 a 可能返回的值
	// ATYPIPv4 is ipv4 address type
	// ATYPIPv4 byte = 0x01 // 4 octets
	// ATYPDomain is domain address type
	// ATYPDomain byte = 0x03 // The first octet of the address field contains the number of octets of name that follow, there is no terminating NUL octet.
	// ATYPIPv6 is ipv6 address type
	// ATYPIPv6 byte = 0x04 // 16 octets
	a, h, p, err := socks5.ParseAddress(addr)
	if err != nil {
		return err
	}
	rawaddr := make([]byte, 0, 7)
	rawaddr = append(rawaddr, a)
	rawaddr = append(rawaddr, h...)
	rawaddr = append(rawaddr, p...)
	// 加密传输请求内容（地址）
	n, err = WriteTo(rc, rawaddr, k, n, true)
	if err != nil {
		return err
	}

	// 如果代理客户端正确接受了 CONNECT 请求，并且成功建立了和后端服务器的 TCP 连接，
	// 它应该返回 200 状态码的应答，按照大多数的约定为 200 Connection Establised\r\n\r\n。
	// 应答也不需要包含其他的头部和 body，因为后续的数据传输都是直接转发的，代理不会分析其中的内容。
	if method == "CONNECT" {
		// 这是返回给访问本代理(系统或浏览器或其它)的应答
		// 给代理用户返回 200 状态码应答
		_, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if err != nil {
			return err
		}
	}
	if method != "CONNECT" {
		// 第四次写入 完整的请求头
		// 如果不是CONNECT 方法把请求头发给代理服务端处理
		n, err = WriteTo(rc, b, k, n, false)
		if err != nil {
			return err
		}
	}

	// 最核心的就是下面这些了
	// 主函数和 goroutine 并行执行
	// 一、 goroutine 负责：
	// 1. 从代理服务端读取加密数据再解密
	// 2. 把解密的数据写给代理用户
	// 3. 重复 步骤1
	// ......
	// 直到本次请求结束（EOF或任何错误）

	// 二、 主函数负责：
	// 1. 从代理用户读取数据
	// 2. 加密数据传输到代理服务端
	// 3. 重复 步骤1
	// ......
	// 直到本次请求结束（EOF或任何错误）

	// 感觉乱吗？
	// 其实一点也不乱，但你会说，怎么不放一块顺序执行呢？非要用goroutine 呢？
	// 我只能说了，除了为效率考虑，就是为了效率考虑，代理客户端接收代理用户的请求
	// 把请求发送给代理客户端都是异步进行，除了为效率考虑，我真不知道为了其它什么！

	// 首先到说上次那个判断是不是代理请求让我绕了一大圈，在服务端怎么看也找不到接收的地方，
	// 实在找不到，硬着头皮往下看，恍然大悟，其实到判断那已经上述步骤
	go func() {
		n := make([]byte, 12)
		if _, err := io.ReadFull(rc, n); err != nil {
			return
		}
		k, err := GetKey(x.Password, n)
		if err != nil {
			log.Println(err)
			return
		}
		var b []byte
		for {
			if x.TCPDeadline != 0 {
				if err := rc.SetDeadline(time.Now().Add(time.Duration(x.TCPDeadline) * time.Second)); err != nil {
					return
				}
			}
			b, n, err = ReadFrom(rc, k, n, false)
			if err != nil {
				return
			}
			if _, err := c.Write(b); err != nil {
				return
			}
		}
	}()

	var bf [1024 * 2]byte
	for {
		if x.TCPDeadline != 0 {
			if err := c.SetDeadline(time.Now().Add(time.Duration(x.TCPDeadline) * time.Second)); err != nil {
				return nil
			}
		}
		i, err := c.Read(bf[:])
		if err != nil {
			return nil
		}
		n, err = WriteTo(rc, bf[0:i], k, n, false)
		if err != nil {
			return nil
		}
	}
	return nil
}

// Shutdown used to stop the client
func (x *Client) Shutdown() error {
	return x.Server.Stop()
}
