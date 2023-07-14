// code is based on the snippet https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
// with a permissive (Public Domain) License.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"CA Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning /*, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth */},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		EmailAddresses:        []string{"iamca@example.com"},
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	// pem encode
	caCertFile, err := os.OpenFile("cacert.pem", os.O_RDWR|os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	pem.Encode(caCertFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyFile, err := os.OpenFile("ca-key.pem", os.O_RDWR|os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		log.Fatal(err)
	}
	defer caPrivKeyFile.Close()
	pem.Encode(caPrivKeyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err := makeCertificate(ca, caPrivKey, "server"); err != nil {
		log.Fatal(err)
	}
	if err := makeCertificate(ca, caPrivKey, "client"); err != nil {
		log.Fatal(err)
	}
}

func makeCertificate(ca *x509.Certificate, caPrivKey *rsa.PrivateKey, outbase string) error {
	var eku x509.ExtKeyUsage
	if outbase == "server" {
		eku = x509.ExtKeyUsageServerAuth
	} else if outbase == "client" {
		eku = x509.ExtKeyUsageClientAuth
	} else {
		log.Fatalf("makeCertificate: unknown outbase parameter %s, supported are 'serfer' or 'client'", outbase)
	}
	// set up the certificate template
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		// KeyUsage:       x509.KeyUsageDigitalSignature,
		EmailAddresses: []string{outbase + "@example.com"},
		DNSNames:       []string{outbase + ".example.com"},
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	certFile, err := os.OpenFile(outbase+".pem", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certFile.Close()
	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to encode cert: %v", err)
	}

	keyFile, err := os.OpenFile(outbase+"-key.pem", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer keyFile.Close()
	err = pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		log.Fatalf("failed to encode private key: %v", err)
	}
	return nil
}
