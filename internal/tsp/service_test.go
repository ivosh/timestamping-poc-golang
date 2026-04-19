package tsp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"slices"

	"github.com/czertainly/signer-poc/internal/tsacrypto"
	"github.com/digitorus/timestamp"
)

// Minimal ASN.1 structs for walking SignedData during signature verification.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs         asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos       []signerInfo  `asn1:"set"`
}

func buildTSQ(t *testing.T) []byte {
	t.Helper()
	h := sha256.Sum256([]byte("hello"))

	nonceBig, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}

	// TimeStampReq ::= SEQUENCE {
	//   version      INTEGER { v1(1) },
	//   messageImprint MessageImprint,
	//   reqPolicy    TSAPolicyId OPTIONAL,
	//   nonce        INTEGER OPTIONAL,
	//   certReq      BOOLEAN OPTIONAL,
	//   extensions   [0] IMPLICIT Extensions OPTIONAL
	// }
	type messageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	type tsReq struct {
		Version        int
		MessageImprint messageImprint
		Nonce          *big.Int `asn1:"optional"`
		CertReq        bool     `asn1:"optional"`
	}

	req := tsReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			},
			HashedMessage: h[:],
		},
		Nonce:   nonceBig,
		CertReq: true,
	}
	der, err := asn1.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSign(t *testing.T) {
	id, err := tsacrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(id)

	tsqDER := buildTSQ(t)

	req, err := timestamp.ParseRequest(tsqDER)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	respDER, err := svc.Sign(req)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// a. Parse response
	ts, err := timestamp.ParseResponse(respDER)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}

	// b. Status granted + serial present
	if ts.SerialNumber == nil {
		t.Fatal("SerialNumber is nil")
	}

	// c. MessageImprint round-trip
	if ts.HashAlgorithm != crypto.SHA256 {
		t.Fatalf("HashAlgorithm: got %v, want SHA256", ts.HashAlgorithm)
	}
	want := sha256.Sum256([]byte("hello"))
	if !bytes.Equal(ts.HashedMessage, want[:]) {
		t.Fatal("HashedMessage mismatch")
	}

	// d. TSA certificate embedded
	if len(ts.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(ts.Certificates))
	}
	if !ts.Certificates[0].Equal(id.Certificate) {
		t.Fatal("embedded certificate does not match TSA identity")
	}

	// e. Signature verification
	var ci contentInfo
	if _, err := asn1.Unmarshal(ts.RawToken, &ci); err != nil {
		t.Fatalf("unmarshal contentInfo: %v", err)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("unmarshal signedData: %v", err)
	}
	if len(sd.SignerInfos) == 0 {
		t.Fatal("no SignerInfos")
	}
	si := sd.SignerInfos[0]

	// Replace [0] context tag with 0x31 (SET) for the digest input.
	raw := slices.Clone(si.SignedAttrs.FullBytes)
	raw[0] = 0x31
	digest := sha512.Sum384(raw)

	pub := id.Certificate.PublicKey.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA384, digest[:], si.Signature); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func buildHTTPRequest(body []byte, contentType string) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "/v1/protocols/tsp/test/sign", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	return req
}

func TestHTTP(t *testing.T) {
	id, err := tsacrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(id)

	tsqDER := buildTSQ(t)

	// Valid request → 200 + correct Content-Type
	req := buildHTTPRequest(tsqDER, "application/timestamp-query")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/timestamp-reply") {
		t.Fatalf("expected application/timestamp-reply, got %q", ct)
	}

	// Wrong Content-Type → 400
	req2 := buildHTTPRequest(tsqDER, "application/octet-stream")
	resp2, err := app.Test(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp2.StatusCode)
	}
}
