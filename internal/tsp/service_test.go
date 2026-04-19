package tsp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"slices"

	"github.com/digitorus/timestamp"
	"github.com/examle.com/timestamping-poc-golang/internal/tsacrypto"
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
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

func buildTSQ(t *testing.T) []byte {
	t.Helper()
	h := sha256.Sum256([]byte("hello"))

	nonceBig, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}

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

func buildTSQWithPolicy(t *testing.T, policy asn1.ObjectIdentifier) []byte {
	t.Helper()
	h := sha256.Sum256([]byte("hello"))

	nonceBig, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}

	type messageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	// RFC 3161: version, messageImprint, reqPolicy (optional), nonce (optional), certReq (optional)
	type tsReqWithPolicy struct {
		Version        int
		MessageImprint messageImprint
		ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
		Nonce          *big.Int              `asn1:"optional"`
		CertReq        bool                  `asn1:"optional"`
	}

	req := tsReqWithPolicy{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			},
			HashedMessage: h[:],
		},
		ReqPolicy: policy,
		Nonce:     nonceBig,
		CertReq:   true,
	}
	der, err := asn1.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSign(t *testing.T) {
	chain, err := tsacrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(chain, DefaultConfig())

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

	// d. Two certs embedded: leaf (index 0) + Root CA (index 1).
	if len(ts.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(ts.Certificates))
	}
	if !ts.Certificates[0].Equal(chain.LeafCert) {
		t.Fatal("embedded leaf certificate does not match TSA chain")
	}
	if !ts.Certificates[1].Equal(chain.CACert) {
		t.Fatal("embedded CA certificate does not match TSA chain")
	}

	// e. Verify the leaf was signed by the CA.
	pool := x509.NewCertPool()
	pool.AddCert(chain.CACert)
	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if _, err := chain.LeafCert.Verify(opts); err != nil {
		t.Fatalf("leaf certificate chain verification failed: %v", err)
	}

	// f. Signature verification
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

	raw := slices.Clone(si.SignedAttrs.FullBytes)
	raw[0] = 0x31
	digest := sha512.Sum384(raw)

	pub := chain.LeafCert.PublicKey.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA384, digest[:], si.Signature); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func buildHTTPRequest(body []byte, contentType string) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/protocols/tsp/test/sign", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	return req
}

func TestHTTP(t *testing.T) {
	chain, err := tsacrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(chain, DefaultConfig())

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

func TestNonceDuplicate(t *testing.T) {
	chain, _ := tsacrypto.Generate()
	svc := NewService(chain, DefaultConfig())

	tsqDER := buildTSQ(t)
	req, _ := timestamp.ParseRequest(tsqDER)

	if _, err := svc.Sign(req); err != nil {
		t.Fatalf("first Sign: %v", err)
	}
	if _, err := svc.Sign(req); !errors.Is(err, ErrDuplicateNonce) {
		t.Fatalf("expected ErrDuplicateNonce, got %v", err)
	}
}

func TestSnowflakeUniqueness(t *testing.T) {
	sf := NewSnowflake()
	const n = 10_000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		v := sf.Generate().String()
		if _, dup := seen[v]; dup {
			t.Fatalf("duplicate serial at iteration %d: %s", i, v)
		}
		seen[v] = struct{}{}
	}
}

func TestSnowflakeMonotonic(t *testing.T) {
	sf := NewSnowflake()
	prev := sf.Generate()
	for i := 0; i < 1000; i++ {
		next := sf.Generate()
		if next.Cmp(prev) <= 0 {
			t.Fatalf("non-monotonic serial: %s then %s", prev, next)
		}
		prev = next
	}
}

func TestTimeQualityRejection(t *testing.T) {
	chain, _ := tsacrypto.Generate()
	svc := NewService(chain, DefaultConfig())

	svc.tq.status.Store(int32(TQFailed))

	tsqDER := buildTSQ(t)
	req, _ := timestamp.ParseRequest(tsqDER)

	_, err := svc.Sign(req)
	if !errors.Is(err, ErrTimeNotAvailable) {
		t.Fatalf("expected ErrTimeNotAvailable, got %v", err)
	}
}

func TestPolicyAccepted(t *testing.T) {
	chain, _ := tsacrypto.Generate()
	cfg := DefaultConfig()
	svc := NewService(chain, cfg)

	tsqDER := buildTSQWithPolicy(t, cfg.DefaultPolicyOID)
	req, _ := timestamp.ParseRequest(tsqDER)

	if _, err := svc.Sign(req); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestPolicyRejected(t *testing.T) {
	chain, _ := tsacrypto.Generate()
	svc := NewService(chain, DefaultConfig())

	foreign := asn1.ObjectIdentifier{1, 9, 9, 9, 9}
	tsqDER := buildTSQWithPolicy(t, foreign)
	req, _ := timestamp.ParseRequest(tsqDER)

	_, err := svc.Sign(req)
	if !errors.Is(err, ErrUnacceptedPolicy) {
		t.Fatalf("expected ErrUnacceptedPolicy, got %v", err)
	}
}
