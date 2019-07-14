package main

import (
	"log"
	"net/http"
)

func main() {
	proxy := NewHTTPProxy()
	log.Fatal(http.ListenAndServe(":8080", proxy))
}
