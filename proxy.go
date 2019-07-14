package main

import (
	"io"
	"log"
	"net/http"
	"os"
)

// HTTPProxy implements http.Handler interface
type HTTPProxy struct {
	transport *http.Transport
	logger    *log.Logger
}

func (proxy *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

// NewHTTPProxy returns a new HTTPProxy
func NewHTTPProxy() *HTTPProxy {
	return &HTTPProxy{
		transport: &http.Transport{},
		logger:    log.New(os.Stderr, "[loxy] ", log.LstdFlags),
	}
}
