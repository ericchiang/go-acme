package letsencrypt

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

// CertificateResponse holds response items after requesting a Certificate.
type CertificateResponse struct {
	Certificate *x509.Certificate
	RetryAfter  int
	URI         string
	StableURI   string
	Issuer      string
}

// Bundle bundles the certificate with the issuer certificate.
func (c *CertificateResponse) Bundle() (bundledPEM []byte, err error) {
	if !c.IsAvailable() {
		return nil, errors.New("Cannot bundle without certificate")
	}

	if c.Issuer == "" {
		return nil, errors.New("Could not bundle certificates. Issuer not found")
	}

	resp, err := http.Get(c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("Error requesting issuer certificate: %s", err)
	}

	defer resp.Body.Close()
	issuerDER, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading issuer certificate: %s", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate.Raw})
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})

	return append(certPEM, issuerPEM...), nil
}

// Retry request retries the certificate if it was unavailable when calling
// NewCertificate or RenewCertificate.
//
// Note: If you are renewing a certificate, LetsEncrypt may return the same
// certificate. You should load your current x509.Certificate and use the
// Equal method to compare to the "new" certificate. If it's identical,
// you'll need to start a new certificate flow.
func (c *CertificateResponse) Retry() error {
	if c.IsAvailable() {
		return errors.New("Aborting retry request. Certificate is already available")
	}

	if c.URI == "" {
		return errors.New("Could not make retry request. No URI available")
	}

	resp, err := http.Get(c.URI)
	if err != nil {
		return fmt.Errorf("Error retrying certificate request: %s", err)
	}

	defer resp.Body.Close()

	// Certificate is available
	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("read response body: %s", err)
		}

		x509Cert, err := x509.ParseCertificate(body)
		if err != nil {
			return fmt.Errorf("Error parsing x509 certificate: %s", err)
		}

		c.Certificate = x509Cert
		c.RetryAfter = 0

		if stableURI := resp.Header.Get("Content-Location"); stableURI != "" {
			c.StableURI = stableURI
		}

		links := parseLinks(resp.Header["Link"])
		c.Issuer = links["up"]

		return nil
	}

	// Certificate still isn't ready.
	if resp.StatusCode == http.StatusAccepted {
		retryAfter, err := strconv.Atoi(resp.Header.Get("Retry-After"))
		if err != nil {
			return fmt.Errorf("Error parsing retry-after header: %s", err)
		}

		c.RetryAfter = retryAfter

		return nil
	}

	return fmt.Errorf("Retry expected status code of %d or %d, given %d", http.StatusOK, http.StatusAccepted, resp.StatusCode)
}

// RetryPoll will attempt to retrieve asynchronous certificates maxRetries times
// and sleep for RetryAfter seconds between requests.
// This method will not make the initial request until the initial
// RetryAfter period elapses.
func (c *CertificateResponse) RetryPoll(maxRetries int) error {
	time.Sleep(time.Duration(c.RetryAfter) * time.Second)

	retries := 0
	for {
		if retries >= maxRetries {
			return fmt.Errorf("max retries of %d", maxRetries)
		}

		if err := c.Retry(); err != nil {
			return err
		}

		// Certificate was returned.
		if c.IsAvailable() {
			return nil
		}

		retries++
		time.Sleep(time.Duration(c.RetryAfter) * time.Second)
	}
}

// IsAvailable returns bool true if CertificateResponse has a certificate
// available. It's a convenience function, but it helps with readability.
func (c *CertificateResponse) IsAvailable() bool {
	return c.Certificate != nil
}
