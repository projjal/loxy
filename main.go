package main

import (
	"flag"
	"log"
	"net/http"
)

// Parameters
var certPath string
var keyPath string
var mitm bool

func init() {
	flag.BoolVar(&mitm, "mitm", true, "Man-in-the-middle https connection")
	flag.StringVar(&certPath, "cert_path", "", "path of PEM encoded certificate file")
	flag.StringVar(&keyPath, "key_path", "", "path of PEM encoded private key")
}

func main() {
	flag.Parse()

	proxy := NewHTTPProxy(mitm, certPath, keyPath)
	log.Fatal(http.ListenAndServe(":8080", proxy))
}
