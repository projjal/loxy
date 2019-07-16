package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"time"
)

func createTLSConfig(host, certPath, keyPath string) *tls.Config {
	ix := strings.Index(host, ":")
	if ix != -1 {
		host = host[:ix]
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Printf("error loading X509 keypair: %s", err.Error())
		return nil
	}

	signedCert, err := signCert(&cert, host)
	if err != nil {
		log.Printf("error signing certificate: %s", err.Error())
		return nil
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{*signedCert}}
	return cfg

}

func signCert(ca *tls.Certificate, host string) (*tls.Certificate, error) {
	x509ca, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}

	validityDate, err := time.Parse("2006-01-02", "2050-01-01")
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write([]byte(host))
	hash := h.Sum(nil)
	serial := new(big.Int)
	serial.SetBytes(hash)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Issuer:                x509ca.Subject,
		Subject:               pkix.Name{Organization: []string{"Loxy mitm proxy"}},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              validityDate,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
		template.Subject.CommonName = host
	}

	var pkey crypto.Signer

	switch ca.PrivateKey.(type) {
	case *rsa.PrivateKey:
		pkey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	case *ecdsa.PrivateKey:
		pkey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	default:
		err := fmt.Errorf("Unsupported key type: %T", ca.PrivateKey)
		return nil, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, x509ca, pkey.Public(), ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{cert, ca.Certificate[0]},
		PrivateKey:  pkey,
	}, nil
}
