# A Let's Encrypt client for Go

[![GoDoc](https://godoc.org/github.com/ericchiang/letsencrypt?status.svg)](https://godoc.org/github.com/ericchiang/letsencrypt)

__NOTE:__ If you're thinking about using this package, I would recommend looking at Russ Cox's [letsencrypt package](https://godoc.org/rsc.io/letsencrypt) first.

## About

This is a client package for Let's Encrypt.

Rather than being a "one click TLS" service like Let's Encrypt's [command line tool](https://github.com/letsencrypt/letsencrypt), this package exposes the functionality defined by the ACME spec. It is up to the user to determine which challenges they support and how they wish to complete them.

Since the [ACME spec](https://github.com/ietf-wg-acme/acme) is still a draft and Let's Encrypt has yet to enter public beta, this package should be regarded as experimental (though it should still work!).

Read more about the package [in this blog post](https://ericchiang.github.io/go/tls/lets/encrypt/letsencrypt/2015/11/13/a-letsencrypt-client-for-go.html).

## Example usage

```go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "log"

    "github.com/ericchiang/letsencrypt"
)

var supportedChallengs = []string{
    letsencrypt.ChallengeHTTP,
    letsencrypt.ChallengeTLSSNI,
}

func main() {
    cli, err := letsencrypt.NewClient("http://localhost:4000/directory")
    if err != nil {
        log.Fatal("failed to create client:", err)
    }

    // Create a private key for your account and register
    accountKey, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
        log.Fatal(err)
    }
    if _, err := cli.NewRegistration(accountKey); err != nil {
        log.Fatal("new registration failed:", err)
    }

    // ask for a set of challenges for a given domain
    auth, _, err := cli.NewAuthorization(accountKey, "dns", "example.org")
    if err != nil {
        log.Fatal(err)
    }
    chals := auth.Combinations(supportedChallenges...)
    if len(chals) == 0 {
        log.Fatal("no supported challenge combinations")
    }

    /*
        review challenge combinations and complete them
    */

    // create a certificate request for your domain
    csr, certKey, err := newCSR()
    if err != nil {
        log.Fatal(err)
    }

    // Request a certificate for your domain
    cert, err := cli.NewCertificate(accountKey, csr)
    if err != nil {
        log.Fatal(err)
    }
    // We've got a certificate. Let's Encrypt!
}

func newCSR() (*x509.CertificateRequest, *rsa.PrivateKey, error) {
    certKey, err := rsa.GenerateKey(rand.Random, 4096)
    if err != nil {
        return nil, nil, err
    }
    template := &x509.CertificateRequest{
        SignatureAlgorithm: x509.SHA256WithRSA,
        PublicKeyAlgorithm: x509.RSA,
        PublicKey:          &certKey.PublicKey,
        Subject:            pkix.Name{CommonName: "example.org"},
        DNSNames:           []string{"example.org"},
    }
    csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, certKey)
    if err != nil {
        return nil, nil, err
    }
    csr, err := x509.ParseCertificateRequest(csrDER)
    if err != nil {
        return nil, nil, err
    }
    return csr, certKey, nil
}
```

## Challenges

### HTTP

HTTP challenges (`http-01`) require provising an HTTP resource at a given path on your domain.

```go
chal := chals[0]
if chal.Type != ChallengeHTTP {
    log.Fatal("this isn't an HTTP challenge!")
}

path, resource, err := chal.HTTP(accountKey)
if err != nil {
    log.Fatal(err)
}

go func() {
    // Listen on HTTP for a request at the given path.
    hf := func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != path {
            http.NotFound(w, r)
            return
        }
        io.WriteString(w, resource)
    }
    log.Fatal(http.ListenAndServe(":80", http.HandlerFunc(hf)))
}()

// Tell the server the challenge is ready and poll the server for updates.
if err := cli.ChallengeReady(accountKey, chal); err != nil {
    // oh no, you failed the challenge
    log.Fatal(err)
}
// The challenge has been verified!
```

### TLS SNI

TLS SNI challenges (`tls-sni-01`) require responding to a given [TLS Server Name Indication](https://en.wikipedia.org/wiki/Server_Name_Indication) request with a specific certificate. These server names will not be for the actual domain begin validated, so the challenge can be completed without certificate errors for users.

```go
chal := chals[0]
if chal.Type != ChallengeTLSSNI {
    log.Fatal("this isn't an TLS SNI challenge!")
}

certs, err := chal.TLSSNI(accountKey)
if err != nil {
    log.Fatal(err)
}

go func() {
    // Configure a custom response function for SNI requests.
    getCertificate := func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
        if cert, ok := certs[clientHello.ServerName]; ok {
            return cert, nil
        }
        return nil, nil
    }
    s := &http.Server{
        Addr:      ":443",
        TLSConfig: &tls.Config{GetCertificate: getCertificate},
        Handler:   http.HandlerFunc(http.NotFound),
    }
    log.Fatal(s.ListenAndServeTLS("self-signed.cert", "self-signed.key"))
}()

// Tell the server the challenge is ready and poll the server for updates.
if err := cli.ChallengeReady(accountKey, chal); err != nil {
    // oh no, you failed the challenge
    log.Fatal(err)
}
// The challenge has been verified!
```

## Running the tests

The test suite runs against an installation of Let's Encrypt's [boulder](https://github.com/letsencrypt/boulder). Follow instructions in that repo for running in development mode on `127.0.0.1:4000`.

Boulder will not issue cerficiates for non-public domains (e.g. `.localdomain`). In addition it keeps a blacklist of domains to not issue certificates for.

Before running boulder, you must edit the base blacklist to allow `example.org` and `localhost.localdomain`.

```
$GOPATH$src/github.com/letsencrypt/boulder/cmd/policy-loader/base-rules.json
```

In order to masqurade as a public domain, the tests require adding an entry to `/etc/hosts` to manually change Boulder's DNS resolution. Specifically, have `example.org` resolve to `127.0.0.1`.

```
$ sudo cat /etc/hosts
127.0.0.1       localhost.localdomain localhost
127.0.0.1       example.org example
::1     localhost6.localdomain6 localhost6
```

If you hit rate limits, shut down the Boulder instance and reload the database with `./test/create_db.sh`.
