package main

import (
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
}

func (proxy *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		proxy.handleHTTPS(w, r)
	} else {
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
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	proxy.logger.Printf("Accepting CONNECT request")
	hjConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

	targetConn, err := net.Dial("tcp", host)
	if err != nil {
		proxy.logger.Printf("error connecting to target after CONNECT: %s", err.Error())
		return
	}
	defer targetConn.Close()

	go func() {
		io.Copy(targetConn, hjConn)
	}()
	// go func() {
	// 	io.Copy(hjConn, targetConn)
	// }()
	io.Copy(hjConn, targetConn)
}

// NewHTTPProxy returns a new HTTPProxy
func NewHTTPProxy() *HTTPProxy {
	return &HTTPProxy{
		transport: &http.Transport{},
		logger:    log.New(os.Stderr, "[loxy] ", log.LstdFlags),
	}
}
