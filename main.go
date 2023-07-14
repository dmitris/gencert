// code is based on the snippet https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
// with a permissive (Public Domain) License.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func main() {
	timestampExtension, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		log.Fatalf("unable to Marshal OID: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"example.com"},
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
				Critical: true,
				Value:    timestampExtension,
			},
		},
		EmailAddresses: []string{"test@example.com"},
	}

	// create our private and public key
	signer, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	// create the CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, signer)
	if err != nil {
		log.Fatal(err)
	}

	// Encode the CSR to PEM format
	csrPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	// Save the CSR to a file
	file, err := os.Create("csr.pem")
	if err != nil {
		fmt.Println("Failed to create file:", err)
		return
	}
	defer file.Close()

	_, err = file.Write(csrPem)
	if err != nil {
		fmt.Println("Failed to write to file:", err)
		return
	}

	fmt.Println("OK")
}
