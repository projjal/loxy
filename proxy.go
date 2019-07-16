package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

// HTTPProxy implements http.Handler interface
type HTTPProxy struct {
	transport *http.Transport
	logger    *log.Logger
	mitm      bool
	certPath  string
	keyPath   string
}

func (proxy *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		proxy.logger.Println("Received CONNECT Request")
		proxy.handleHTTPS(w, r)
	} else {
		proxy.logger.Println("Received HTTP Request")
		resp, err := proxy.transport.RoundTrip(r)
		if err != nil {
			proxy.logger.Printf("error received: %s", err.Error())
			return
		}

		header := w.Header()
		for k, v := range resp.Header {
			for _, val := range v {
				header.Add(k, val)
			}
		}

		_, err = io.Copy(w, resp.Body)

		if err = resp.Body.Close(); err != nil {
			proxy.logger.Printf("error closing response body")
		}
		proxy.logger.Printf("success")
	}
}

func (proxy *HTTPProxy) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		proxy.logger.Printf("doesn't supprt hijacking")
		return
	}
	hjConn, _, err := hj.Hijack()
	if err != nil {
		proxy.logger.Printf("error hijacking connection: %s", err.Error())
		return
	}
	defer hjConn.Close()

	host := r.URL.Host

	proxy.logger.Println("Accepting CONNECT request")
	hjConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

	if proxy.mitm {
		proxy.mitmHTTPS(hjConn, host)
	} else {
		if !strings.Contains(host, ":") {
			host += ":80"
		}
		targetConn, err := net.Dial("tcp", host)
		if err != nil {
			proxy.logger.Printf("error connecting to target after CONNECT: %s", err.Error())
			return
		}
		defer targetConn.Close()

		go func() {
			io.Copy(targetConn, hjConn)
		}()
		io.Copy(hjConn, targetConn)
	}
}

func (proxy *HTTPProxy) mitmHTTPS(hjConn net.Conn, host string) {
	cfg := createTLSConfig(host, proxy.certPath, proxy.keyPath)
	tlsConn := tls.Server(hjConn, cfg)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		proxy.logger.Printf("error doing tls handshake: %s", err.Error())
		return
	}

	tlsReader := bufio.NewReader(tlsConn)

	for {
		req, err := http.ReadRequest(tlsReader)
		if err != nil && err == io.EOF {
			break
		}
		if err != nil {
			proxy.logger.Printf("error creating request from tlsConn: %s", err.Error())
			return
		}

		resp, err := proxy.transport.RoundTrip(req)
		if err != nil {
			proxy.logger.Printf("error in upstream roundtrip: %s", err.Error())
			return
		}

		if err = resp.Write(tlsConn); err != nil {
			proxy.logger.Printf("error writing response to tlsConn: %s", err.Error())
			return
		}
	}
}

// NewHTTPProxy returns a new HTTPProxy
func NewHTTPProxy(mitm bool, certPath, keyPath string) *HTTPProxy {
	return &HTTPProxy{
		transport: &http.Transport{},
		logger:    log.New(os.Stderr, "[loxy] ", log.LstdFlags),
		mitm:      mitm,
		certPath:  certPath,
		keyPath:   keyPath,
	}
}
