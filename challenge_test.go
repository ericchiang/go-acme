package letsencrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ericchiang/letsencrypt/Godeps/_workspace/src/github.com/miekg/dns"
	"strings"
	"sync"
)

// Specified in boulder's configuration
// See $GOATH/src/github.com/letsencrypt/boulder/test/boulder-config.json
var (
	httpPort        int = 5002
	httpsPort       int = 5001
	dnsPort         int = 8053
	txtRecords          = map[string]string{}
	txtRecordsMutex     = sync.RWMutex{}
)

func TestHTTPChallenge(t *testing.T) {
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
}

func TestTLSSNIChallenge(t *testing.T) {
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

	chals := auth.Combinations(ChallengeTLSSNI)
	if len(chals) == 0 || len(chals[0]) != 1 {
		t.Fatal("no supported challenges")
	}
	chal := chals[0][0]
	certs, err := chal.TLSSNI(priv)
	if err != nil {
		t.Fatal(err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{},
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, ok := certs[clientHello.ServerName]
			if ok {
				return cert, nil
			}
			t.Errorf("got unknown SNI server name: %v", clientHello.ServerName)
			return nil, nil
		},
	}
	for _, cert := range certs {
		tlsConf.Certificates = append(tlsConf.Certificates, *cert)
	}

	list, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort), tlsConf)
	if err != nil {
		t.Errorf("listening on port %d: %v", httpsPort, err)
		return
	}
	defer list.Close()
	go func() {
		for {
			conn, err := list.Accept()
			if err != nil {
				return
			}
			if conn, ok := conn.(*tls.Conn); ok {
				// must get past the handshake
				if err := conn.Handshake(); err != nil {
					t.Errorf("handshake error: %v", err)
				}
			} else {
				t.Errorf("connection is not a tls connection")
			}
			conn.Close()
		}
	}()

	if err := cli.ChallengeReady(priv, chal); err != nil {
		t.Fatal(err)
	}
}

func dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	for _, q := range r.Question {
		if q.Qtype != dns.TypeTXT {
			continue
		}
		txtRecordsMutex.RLock()
		value, present := txtRecords[q.Name]
		txtRecordsMutex.RUnlock()
		if !present {
			continue
		}
		record := new(dns.TXT)
		record.Hdr = dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		}
		record.Txt = []string{value}
		m.Answer = append(m.Answer, record)
	}
	w.WriteMsg(m)
	return
}

func TestDNSChallenge(t *testing.T) {
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

	chals := auth.Combinations(ChallengeDNS)
	if len(chals) == 0 || len(chals[0]) != 1 {
		t.Fatal("no supported challenges")
	}
	chal := chals[0][0]
	subdomain, txtval, err := chal.DNS(priv)
	if err != nil {
		t.Fatal(err)
	}

	txtRecordsMutex.Lock()
	// end host in a period so its fqdn for dns question
	fd := strings.Join([]string{subdomain, testDomain, ""}, ".")
	txtRecords[strings.ToLower(fd)] = txtval
	txtRecordsMutex.Unlock()

	dns.HandleFunc(".", dnsHandler)
	dnsServer := &dns.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", dnsPort),
		Net:  "tcp",
	}
	go func() {
		err := dnsServer.ListenAndServe()
		if err != nil {
			fmt.Println(err)
			return
		}
	}()

	if err := cli.ChallengeReady(priv, chal); err != nil {
		t.Fatal(err)
	}
}
