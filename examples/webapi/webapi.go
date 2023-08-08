package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
)

func hello(w http.ResponseWriter, req *http.Request) {
	log.Printf("HTTP REQ: %s -> %s, %s", req.RemoteAddr, req.Host, req.URL.String())

	fmt.Fprintf(w, "Hi there.\n")
}

func headers(w http.ResponseWriter, req *http.Request) {
	log.Printf("HTTP REQ: %s -> %s, %s", req.RemoteAddr, req.Host, req.URL.String())

	for name, headers := range req.Header {
		for _, h := range headers {
			log.Printf("HTTP Header %v: %v\n", name, h)
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}

func dumpConn(c net.Conn, depth int) {
	if c == nil {
		return
	}

	switch c.(type) {
	case *proxyproto.Conn:
		lead := strings.Repeat("=", depth)
		pc, _ := c.(*proxyproto.Conn)
		pHeader := pc.ProxyHeader()

		if pHeader == nil {
			log.Printf(lead+">ProxyConn: depth:%d, ver:-1, %s -> %s", depth,
				c.RemoteAddr().String(), c.LocalAddr().String())
		} else {
			log.Printf(lead+">ProxyConn: depth:%d, ver:%d, proto:0x%x %s -> %s",
				depth,
				pHeader.Version,
				pHeader.TransportProtocol,
				c.RemoteAddr().String(), c.LocalAddr().String())

			tlvs, _ := pHeader.TLVs()
			log.Printf(lead+">TLV cnt: %d", len(tlvs))

			for i, tlv := range tlvs {
				log.Printf(lead+">TLV(%d): type:0x%X, val=0x%X", i+1, tlv.Type, tlv.Value)
			}
		}

		nc, _ := pc.TCPConn()
		dumpConn(nc, depth+1)
	case *tls.Conn:
		lead := strings.Repeat("=", depth)
		log.Printf(lead+">TLSConn: depth:%d, %s -> %s", depth, c.RemoteAddr().String(), c.LocalAddr().String())
		nc := c.(*tls.Conn).NetConn()
		dumpConn(nc, depth+1)
	case *net.TCPConn:
		lead := strings.Repeat("=", depth)
		log.Printf(lead+">TCPConn: depth:%d, %s -> %s", depth, c.RemoteAddr().String(), c.LocalAddr().String())
	default:
		lead := strings.Repeat("=", depth)
		log.Printf(lead+">Unknow: depth:%d, %s -> %s", depth, c.RemoteAddr().String(), c.LocalAddr().String())
	}
}

func serverProxyProtocol(ctx context.Context, wg *sync.WaitGroup, addr string, ssl bool, ppv int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", hello)
	mux.HandleFunc("/hello", hello)
	mux.HandleFunc("/headers", headers)

	server := http.Server{
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 10 * time.Second,
		Addr:         addr,
		Handler:      mux,
		//TLSConfig:    &tls.Config{InsecureSkipVerify: true},
		ConnState: func(c net.Conn, s http.ConnState) {
			if s == http.StateNew {
				log.Printf("new HTTPConn: %s -> %s", c.RemoteAddr().String(), c.LocalAddr().String())
				dumpConn(c, 1)
			}
		},
	}

	var ln net.Listener
	tcpListen, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Printf("failed to listen: %s, err=%s", server.Addr, err)
		return
	}

	ln = tcpListen

	if ppv > 0 {
		proxyListener := &proxyproto.Listener{
			Listener:          tcpListen,
			ReadHeaderTimeout: 10 * time.Second,
		}

		ln = proxyListener
	}

	wg.Add(1)

	go func() {
		defer wg.Done()

		var err1 error
		if ssl {
			log.Printf("Start HTTPS Server %s, ssl=%v, ppv=%d", server.Addr, ssl, ppv)
			err1 = server.ServeTLS(ln, "server.crt", "server.key")
		} else {
			log.Printf("Start HTTP Server %s, ssl=%v, ppv=%d", server.Addr, ssl, ppv)
			err1 = server.Serve(ln)
		}

		if err1 != nil {
			log.Printf("failed to start the server: %s, err=%s", server.Addr, err1)
		}

		log.Printf("Stop Server %s, ssl=%v, ppv=%d", addr, ssl, ppv)
	}()

	<-ctx.Done()
	server.Close()
}

func startHttpServer(addr string, ssl bool, ppv int) {
	wg := sync.WaitGroup{}
	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	serverCtx, serverStop := context.WithCancel(context.Background())

	go serverProxyProtocol(serverCtx, &wg, addr, ssl, ppv)

	/*
		// no proxy protocol
		go serverProxyProtocol(serverCtx, &wg, "0.0.0.0:10080", false, 0)
		//go serverProxyProtocol(serverCtx, &wg, "0.0.0.0:10443", true, 0)

		// with proxy protocol
		go serverProxyProtocol(serverCtx, &wg, "0.0.0.0:18091", false, 2)
		//go serverProxyProtocol(serverCtx, &wg, "0.0.0.0:18443", true, 2)
	*/

	go func() {
		sig := <-sigs
		fmt.Println()
		log.Printf("Got signal: %s", sig)
		serverStop()
	}()

	<-serverCtx.Done()
	wg.Wait()
}

/////////////////////

func sendProxyProtocolV1(conn net.Conn) error {
	ip, err := net.ResolveTCPAddr("tcp", "1.1.1.1:1234")
	header := &proxyproto.Header{
		Version:           1,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		//SourceAddr:        conn.LocalAddr(),
		SourceAddr:      ip,
		DestinationAddr: conn.RemoteAddr(),
	}

	wl, err := header.WriteTo(conn)
	if err != nil {
		return err
	}

	log.Printf("Put Proxy Protocol V1: sent %d bytes, SrcIp: %s", wl, ip.String())
	return nil
}

func setTlvAws(tlvs []proxyproto.TLV) []proxyproto.TLV {
	tmp_vpce_id := []byte{0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78}
	vpce_id := proxyproto.TLV{
		Type: proxyproto.PP2Type(0xea), // PP2_TYPE_AWS, 0xea
	}

	//val := []byte{0x01}                         //PP2_SUBTYPE_AWS_VPCE_ID, 0x01
	val := []byte{0x70}
	vpce_id.Value = append(val, tmp_vpce_id...) // vpce_id

	tlvs = append(tlvs, vpce_id)

	log.Printf("  TLVs: type=0x%X, val=0x%X", vpce_id.Type, vpce_id.Value)

	return tlvs
}

func CalcCrc(data []byte) {
	result := crc32.Checksum(data, crc32.MakeTable(crc32.IEEE))
	idx := len(data) - 4

	binary.LittleEndian.PutUint32(data[idx:], result)

	log.Printf("  CRC: 0x%X", data[idx:])
}

func setTlvCrc(tlvs []proxyproto.TLV) []proxyproto.TLV {
	tlv := proxyproto.TLV{
		Type:  proxyproto.PP2Type(0x03),
		Value: make([]byte, 4),
	}

	tlvs = append(tlvs, tlv)

	log.Printf("  TLVs: type=0x%X, val=0x%X", tlv.Type, tlv.Value)

	return tlvs
}

func setTlvAlpn(tlvs []proxyproto.TLV) []proxyproto.TLV {
	//[]proxyproto.PP2Type{proxyproto.PP2_TYPE_CRC32C, PP2_TYPE_AWS, proxyproto.PP2_TYPE_NOOP},

	/*
		func vpceTLV(vpce string) []byte {
		tlv := []byte{
			PP2_TYPE_AWS, 0x00, 0x00, PP2_SUBTYPE_AWS_VPCE_ID,
		}
		binary.BigEndian.PutUint16(tlv[1:3], uint16(len(vpce)+1)) // +1 for subtype
		return append(tlv, []byte(vpce)...)
	*/

	tlv := proxyproto.TLV{
		Type:  proxyproto.PP2Type(0x01),
		Value: []byte{0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78},
	}

	tlvs = append(tlvs, tlv)

	log.Printf("  TLVs: type=0x%X, val=0x%X", tlv.Type, tlv.Value)
	return tlvs
}

func setTlvUniqueId(tlvs []proxyproto.TLV) []proxyproto.TLV {
	tlv := proxyproto.TLV{
		Type:  proxyproto.PP2Type(0x05),
		Value: []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x08},
	}

	tlvs = append(tlvs, tlv)

	log.Printf("  TLVs: type=0x%X, val=0x%X", tlv.Type, tlv.Value)
	return tlvs
}

func checkTlvs(header *proxyproto.Header) {
	buf, err := header.Format()
	if err != nil {
		log.Printf("error: %s ", err)
		return
	}

	log.Printf("buf: len=%d, 0x%X", len(buf), buf)

	tlvs, err := proxyproto.SplitTLVs(buf)
	log.Printf("TLV cnt: %d", len(tlvs))
	for i, tlv := range tlvs {
		log.Printf(">TLV(%d): type:0x%X, val=0x%X", i+1, tlv.Type, tlv.Value)
	}
}

func sendProxyProtocolV2(conn net.Conn, addrType string, enableTlvs bool) error {
	var af proxyproto.AddressFamilyAndProtocol
	var src, dst net.Addr
	var err error

	switch addrType {
	default: // ipv4
		af = proxyproto.TCPv4
		src, _ = net.ResolveTCPAddr("tcp", "1.1.1.1:5678")
		dst, _ = net.ResolveTCPAddr("tcp", "2.2.2.1:3333")

	case "6":
		af = proxyproto.TCPv6
		src, err = net.ResolveTCPAddr("tcp6", "[fff0:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:5678")
		if err != nil {
			log.Printf("failed to set src: %v \n", err)
		}
		dst, _ = net.ResolveTCPAddr("tcp6", "[ffff:fff0:ffff:ffff:ffff:ffff:ffff:ffff]:3333")

	case "u":
		af = proxyproto.UnixStream
		src = &net.UnixAddr{
			Name: "this_is_unix_socket_address_for_source",
		}

		dst = &net.UnixAddr{
			Name: "this_is_unix_socket_address_for_dest",
		}

	}

	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: af,
		SourceAddr:        src,
		DestinationAddr:   dst,

		//SourceAddr:        conn.LocalAddr(),
		//DestinationAddr: conn.RemoteAddr(),
	}

	log.Printf("Proxy Protocol V2: proto:0x%x, Src: %s, Dst: %s",
		header.TransportProtocol,
		header.SourceAddr.String(), header.DestinationAddr.String())

	var enableCrc bool = false

	if enableTlvs == true {
		tlvs := []proxyproto.TLV{}

		tlvs = setTlvAlpn(tlvs)
		tlvs = setTlvUniqueId(tlvs)
		tlvs = setTlvAws(tlvs)

		if enableCrc {
			// be the last
			tlvs = setTlvCrc(tlvs)
		}

		err = header.SetTLVs(tlvs)
		if err != nil {
			log.Printf("failed to set TLV: %s\n", err)
		}

		//checkTlvs(header)
	}

	/*
		wl, err := header.WriteTo(conn)
		if err != nil {
			return err
		}

		log.Printf("Sent %d bytes", wl)
	*/

	buf, err := header.Format()
	if err != nil {
		return err
	}

	l := len(buf)
	log.Printf("header size=%d", l)

	if l%4 != 0 {
	}

	if enableCrc {
		CalcCrc(buf)
	}

	wl, err := bytes.NewBuffer(buf).WriteTo(conn)
	log.Printf("Sent %d bytes", wl)

	return nil
}

func initSslConfig() (*tls.Config, error) {
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	var cert tls.Certificate
	cert, err = tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		return nil, err
	}

	conf := &tls.Config{
		RootCAs:            caCertPool,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	return conf, nil
}

func initSsl(tr *http.Transport) error {
	conf, err := initSslConfig()
	if err != nil {
		return err
	}

	tr.TLSClientConfig = conf
	return nil
}

func httpClient(urlAddr string, ssl bool, ppv int, addrType string, enableTlvs bool) {
	log.Printf("HTTP Client: ssl:%v, ppv:%d, addrType:%s", ssl, ppv, addrType)

	tr := &http.Transport{}

	if true {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).Dial(network, addr)
			if err != nil {
				log.Printf("failed to connect the server: %s, err=%s", addr, err)
				return nil, err
			}

			log.Printf("Connected: %s -> %s", conn.LocalAddr().String(), conn.RemoteAddr().String())

			switch ppv {
			// version 1
			case 1:
				err = sendProxyProtocolV1(conn)
			// version 2
			case 2:
				err = sendProxyProtocolV2(conn, addrType, enableTlvs)
			default:
				err = nil
				// no proxy any more
				//return conn, nil
			}

			if err != nil {
				conn.Close()
				return nil, err
			}

			/*
				if ssl {
					log.Printf("Start HTTPS Client %s, ssl=%v, ppv=%d", urlAddr, ssl, ppv)

					conf, confErr := initSslConfig()
					if confErr != nil {
						conn.Close()
						return nil, err
					}

					tlsConn := tls.Client(conn, conf)
					if err := tlsConn.Handshake(); err != nil {
						conn.Close()
						return nil, err
					}
					conn = tlsConn
				}
			*/

			return conn, nil
		}
	}

	if ssl {
		log.Printf("Start HTTPS Client %s, ssl=%v, ppv=%d", urlAddr, ssl, ppv)
		err := initSsl(tr)
		if err != nil {
			log.Printf("Error: %s", err)
			return
		}

	} else {
		log.Printf("Start HTTP Client %s, ssl=%v, ppv=%d", urlAddr, ssl, ppv)
	}

	client := http.Client{
		Transport: tr,
		Timeout:   4 * time.Second,
	}

	start := time.Now()
	resp, http_err := client.Get(urlAddr)

	if http_err != nil {
		log.Printf("Error: %v", http_err)
		return
	}

	r, read_err := ioutil.ReadAll(resp.Body)
	elapsed := time.Since(start)

	if resp != nil {
		defer resp.Body.Close()
	}

	if read_err != nil {
		log.Printf("Error: %v, Time taken: %v", read_err, elapsed)
		return
	}

	log.Printf("End HTTP(s) Client: Status: %v, Time taken: %v", resp.Status, elapsed)
	log.Printf("=== Response ===")
	log.Printf("%s", "\n"+string(r))
	log.Printf("================")
}

func setupLogFile(logFileName string) func() {
	if logFileName == "" {
		return func() {
		}
	}
	/*
	   // Log to syslog
	   logFile, err := syslog.New(syslog.LOG_SYSLOG, "webapi")
	   if err != nil {
	       log.Fatalln("Unable to set logfile:", err.Error())
	   }
	*/

	logFile, err := os.OpenFile(logFileName, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Panic(err)
	}

	// + set log flag
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	// set the log output
	log.SetOutput(logFile)

	return func() {
		logFile.Close()
	}
}

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	mode := flag.String("mode", "server", "run mode: server/client")
	svcaddr := flag.String("svcaddr", "0.0.0.0:80", "service addr")

	ssl := flag.Bool("ssl", false, "Use HTTPS")
	url := flag.String("url", "", "url to connect")
	ppv := flag.Int("ppv", 0, "proxy protocol version: 0,1,2, 0: disable")
	enableTlvs := flag.Bool("tlv", true, "send TLVs")
	addrType := flag.String("ppv-addr", "4", "IP Address version: 4,6,u")

	logFileName := flag.String("logfile", "", "log file")

	flag.Parse()

	fn := setupLogFile(*logFileName)
	defer fn()

	switch *mode {
	case "server":
		startHttpServer(*svcaddr, *ssl, *ppv)
	case "client":
		httpClient(*url, *ssl, *ppv, *addrType, *enableTlvs)
	default:
		fmt.Printf("Unknown mode: %s \n", *mode)
	}
}
