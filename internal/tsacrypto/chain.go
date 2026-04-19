package tsacrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// TSAChain holds a two-level PKI hierarchy generated at startup.
type TSAChain struct {
	// Root CA — kept only to sign the leaf; never exposed to clients directly.
	CAKey  *rsa.PrivateKey
	CACert *x509.Certificate

	// TSA leaf — used for all signing operations.
	LeafKey  *rsa.PrivateKey
	LeafCert *x509.Certificate
}

// Generate creates a fresh Root CA and a TSA leaf certificate signed by it.
// Both are RSA-2048. The leaf carries the id-kp-timeStamping EKU as required
// by RFC 3161 §2.3.
func Generate() (*TSAChain, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	caSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "TSA-PoC Root CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, err
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	leafSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "TSA-PoC Timestamping"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		return nil, err
	}

	return &TSAChain{
		CAKey:    caKey,
		CACert:   caCert,
		LeafKey:  leafKey,
		LeafCert: leafCert,
	}, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
