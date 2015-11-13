package letsencrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

var (
	testDomain = "example.org"
	testURL    = "http://localhost:4000/directory"
)

func TestNewClient(t *testing.T) {
	if _, err := NewClient(testURL); err != nil {
		t.Fatal(err)
	}
}

func TestRegister(t *testing.T) {
	cli, err := NewClient(testURL)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := cli.NewRegistration(priv)
	if err != nil {
		t.Fatal(err)
	}
	reg.Contact = []string{"mailto:cert-admin@example.com", "tel:+12025551212"}
	updatedReg, err := cli.UpdateRegistration(priv, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(updatedReg.Contact) != 2 {
		t.Errorf("expected update to add two contacts, got %s", updatedReg.Contact)
	}
	recoveredReg, err := cli.NewRegistration(priv)
	if err != nil {
		t.Errorf("expected recovered reg to have two contacts, got %s", recoveredReg.Contact)
	}
}

func TestNewAuthorization(t *testing.T) {
	cli, err := NewClient(testURL)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.NewRegistration(priv); err != nil {
		t.Fatal(err)
	}

	auth, authURL, err := cli.NewAuthorization(priv, "dns", testDomain)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = cli.NewAuthorization(priv, "dns", testDomain); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.NewRegistration(priv); err != nil {
		t.Fatal(err)
	}
	recoveredAuth, err := cli.Authorization(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Identifier.Value != recoveredAuth.Identifier.Value {
		t.Error("recovered auth did not match original auth")
	}
}

func TestAuthorizationChallenges(t *testing.T) {
	cli, err := NewClient(testURL)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.NewRegistration(priv); err != nil {
		t.Fatal(err)
	}

	auth, _, err := cli.NewAuthorization(priv, "dns", testDomain)
	if err != nil {
		t.Fatal(err)
	}
	for _, chal := range auth.Challenges {
		if _, err := cli.Challenge(chal.URI); err != nil {
			t.Errorf("failed to get challenge from URI %s: %v", chal.URI, err)
		}
	}
}

func TestNewCertificate(t *testing.T) {
	requiresEtcHostsEdits(t)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	cli, err := NewClient(testURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.NewRegistration(priv); err != nil {
		t.Fatal(err)
	}
	auth, _, err := cli.NewAuthorization(priv, "dns", testDomain)
	if err != nil {
		t.Fatal(err)
	}

	chals := auth.Combinations(ChallengeHTTP)
	if len(chals) == 0 || len(chals[0]) != 1 {
		t.Fatal("no supported challenges")
	}
	chal := chals[0][0]
	urlPath, resource, err := chal.HTTP(priv)
	if err != nil {
		t.Fatal(err)
	}

	hf := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != urlPath {
			t.Error("server request did not match path. expecting", urlPath, "got", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, resource)
	}

	list, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort))
	if err != nil {
		t.Fatal("listening on port 5002", err)
	}

	s := &httptest.Server{
		Listener: list,
		Config:   &http.Server{Handler: http.HandlerFunc(hf)},
	}
	s.Start()
	defer s.Close()

	if err := cli.ChallengeReady(priv, chal); err != nil {
		t.Fatal(err)
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &certKey.PublicKey,
		Subject:            pkix.Name{CommonName: testDomain},
		DNSNames:           []string{testDomain},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, certKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := cli.NewCertificate(priv, csr)
	if err != nil {
		t.Fatal(err)
	}
	contains := func(sli []string, ele string) bool {
		for _, e := range sli {
			if ele == e {
				return true
			}
		}
		return false
	}
	if !contains(cert.DNSNames, testDomain) {
		t.Errorf("returned cert was not for test domain")
	}

	certPEM := pemEncode(cert.Raw, "CERTIFICATE")
	certKeyPEM := pemEncode(x509.MarshalPKCS1PrivateKey(certKey), "RSA PRIVATE KEY")
	if _, err := tls.X509KeyPair(certPEM, certKeyPEM); err != nil {
		t.Errorf("private key did not match returned cert")
	}
}

func TestParseLink(t *testing.T) {
	tests := []struct {
		link string
		ok   bool
		url  string
		rel  string
	}{
		{`<http://127.0.0.1:4000/acme/new-authz>;rel="next"`, true, "http://127.0.0.1:4000/acme/new-authz", "next"},
		{`<http://127.0.0.1:4001/terms/v1>;rel="terms-of-service"`, true, "http://127.0.0.1:4001/terms/v1", "terms-of-service"},
		{`<http://127.0.0.1:4001/terms/v1>; rel="terms-of-service"`, true, "http://127.0.0.1:4001/terms/v1", "terms-of-service"},
	}
	for _, test := range tests {
		url, rel, err := parseLink(test.link)
		if err == nil && !test.ok {
			t.Errorf("expected link to be bad: %s", test.link)
			continue
		}
		if err != nil && test.ok {
			t.Errorf("could not parse link: %s", test.link)
			continue
		}
		if err != nil {
			continue
		}
		if test.url != url {
			t.Errorf("expected link to produce url '%s' got '%s'", test.url, url)
		}
		if test.rel != rel {
			t.Errorf("expected link to produce rel '%s' got '%s'", test.rel, rel)
		}
	}
}

func requiresEtcHostsEdits(t *testing.T) {
	addrs, err := net.LookupHost(testDomain)
	if err != nil || len(addrs) != 1 || addrs[0] != "127.0.0.1" {
		t.Skip("/etc/hosts file not properly configured, skipping test. see README for required edits")
	}
	return
}
