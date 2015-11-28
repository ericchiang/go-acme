package letsencrypt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ericchiang/letsencrypt/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/ericchiang/letsencrypt/internal/base64"
)

const jwsContentType = "application/jose+jws"

const (
	resourceNewRegistration      = "new-reg"
	resourceRecoverRegistation   = "recover-reg"
	resourceNewAuthorization     = "new-authz"
	resourceNewCertificate       = "new-cert"
	resourceNewRevokeCertificate = "revoke-cert"
	resourceRegistration         = "reg"
	resourceAuthorization        = "authz"
	resourceChallenge            = "challenge"
	resourceCertificate          = "cert"
)

type directory struct {
	NewRegistration      string `json:"new-reg"`
	RecoverRegistation   string `json:"recover-reg"`
	NewAuthorization     string `json:"new-authz"`
	NewCertificate       string `json:"new-cert"`
	NewRevokeCertificate string `json:"revoke-cert"`
	Registration         string `json:"reg"`
	Authorization        string `json:"authz"`
	Challenge            string `json:"challenge"`
	Certificate          string `json:"cert"`
	Terms                string `json:"terms"`
}

// Paths taken directly from boulder's source code.
// There are quite a few paths missing in the /directory object
// for boulder's current implementation.
// When those are missing default to these.
// See: https://github.com/letsencrypt/boulder/issues/754
const (
	boulderDirectoryPath  = "/directory"
	boulderNewRegPath     = "/acme/new-reg"
	boulderRegPath        = "/acme/reg/"
	boulderNewAuthzPath   = "/acme/new-authz"
	boulderAuthzPath      = "/acme/authz/"
	boulderNewCertPath    = "/acme/new-cert"
	boulderCertPath       = "/acme/cert/"
	boulderRevokeCertPath = "/acme/revoke-cert"
	boulderTermsPath      = "/terms"
	boulderIssuerPath     = "/acme/issuer-cert"
	boulderBuildIDPath    = "/build"
)

func newDefaultDirectory(baseURL *url.URL) directory {
	pathToURL := func(path string) string {
		var u url.URL
		u = *baseURL
		u.Path = path
		return u.String()
	}

	return directory{
		NewRegistration:      pathToURL(boulderNewRegPath),
		NewAuthorization:     pathToURL(boulderNewAuthzPath),
		NewCertificate:       pathToURL(boulderNewCertPath),
		NewRevokeCertificate: pathToURL(boulderRevokeCertPath),
		Registration:         pathToURL(boulderRegPath),
		Authorization:        pathToURL(boulderAuthzPath),
		Certificate:          pathToURL(boulderCertPath),
		Terms:                pathToURL(boulderTermsPath),
	}
}

// Client is a client for a single ACME server.
type Client struct {
	// PollInterval determines how quickly the client will
	// request updates on a challenge from the ACME server.
	// If unspecified, it defaults to 500 milliseconds.
	PollInterval time.Duration
	// Amount of time after the client notifies the server a challenge is
	// ready, and when it will stop checking for updates.
	// If unspecified, it defaults to 30 seconds.
	PollTimeout time.Duration

	resources directory

	client      *http.Client
	nonceSource jose.NonceSource

	terms string
}

// Terms returns the URL of the server's terms of service.
// All accounts registered using this client automatically
// accept these terms.
func (c *Client) Terms() string {
	return c.terms
}

// NewClient creates a client of a ACME server by querying the server's
// resource directory and attempting to resolve the URL of the terms of service.
func NewClient(directoryURL string) (*Client, error) {
	u, err := url.Parse(directoryURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse URL %s: %v", directoryURL, err)
	}
	if u.Path == "" {
		u.Path = boulderDirectoryPath
	}
	// TODO: make underlying transport configurable
	nrt := newNonceRoundTripper(nil)

	c := &Client{
		client:      &http.Client{Transport: nrt},
		resources:   newDefaultDirectory(u),
		nonceSource: nrt,
	}

	resp, err := c.client.Get(directoryURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkHTTPError(resp, http.StatusOK); err != nil {
		return nil, err
	}

	if err := json.NewDecoder(resp.Body).Decode(&c.resources); err != nil {
		return nil, fmt.Errorf("could not decode body: %v %s", err, resp.Body)
	}

	termsResp, err := c.client.Get(c.resources.Terms)
	if err != nil {
		return nil, fmt.Errorf("GET failed: %v", err)
	}
	defer termsResp.Body.Close()
	if err := checkHTTPError(termsResp, http.StatusOK); err != nil {
		return nil, fmt.Errorf("failed to get terms of service: %v", err)
	}
	c.terms = termsResp.Request.URL.String()

	return c, nil
}

// UpdateRegistration sends the updated registration object to the server.
func (c *Client) UpdateRegistration(accountKey interface{}, reg Registration) (Registration, error) {
	url := c.resources.Registration + strconv.Itoa(reg.Id)
	return c.registration(accountKey, reg, resourceRegistration, url)
}

// NewRegistration registers a key pair with the ACME server.
// If the key pair is already registered, the registration object is recovered.
func (c *Client) NewRegistration(accountKey interface{}) (reg Registration, err error) {
	reg, err = c.registration(accountKey, Registration{}, resourceNewRegistration, c.resources.NewRegistration)
	if err != nil || reg.Agreement == c.Terms() {
		return
	}
	reg.Agreement = c.Terms()
	reg, err = c.UpdateRegistration(accountKey, reg)
	return reg, err
}

func (c *Client) registration(accountKey interface{}, reg Registration, resource, url string) (Registration, error) {
	reg.Resource = resource
	sig, err := c.signObject(accountKey, &reg)
	if err != nil {
		return Registration{}, err
	}
	resp, err := c.client.Post(url, jwsContentType, strings.NewReader(sig))
	if err != nil {
		return Registration{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict && resource == resourceNewRegistration {
		return c.registration(accountKey, Registration{}, resourceRegistration, resp.Header.Get("Location"))
	}

	statusExp := http.StatusCreated
	if resource == resourceRegistration {
		statusExp = http.StatusAccepted
	}

	if err := checkHTTPError(resp, statusExp); err != nil {
		return Registration{}, err
	}

	var updatedReg Registration
	if err := json.NewDecoder(resp.Body).Decode(&updatedReg); err != nil {
		return Registration{}, fmt.Errorf("unmarshalling response body: %v", err)
	}

	return updatedReg, nil
}

// NewAuthorization requests a set of challenges from the server to prove
// ownership of a given resource.
// Only known type is 'dns'.
//
// NOTE: Currently the only way to recover an authorization object is with
// the returned authorization URL.
func (c *Client) NewAuthorization(accountKey interface{}, typ, val string) (auth Authorization, authURL string, err error) {
	type Identifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}

	data := struct {
		Resource   string     `json:"resource"`
		Identifier Identifier `json:"identifier"`
	}{
		resourceNewAuthorization,
		Identifier{typ, val},
	}
	payload, err := c.signObject(accountKey, &data)
	if err != nil {
		return auth, "", err
	}
	resp, err := c.client.Post(c.resources.NewAuthorization, jwsContentType, strings.NewReader(payload))
	if err != nil {
		return auth, "", err
	}
	defer resp.Body.Close()
	if err = checkHTTPError(resp, http.StatusCreated); err != nil {
		return auth, "", err
	}

	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		return auth, "", fmt.Errorf("decoding response body: %v", err)
	}
	return auth, resp.Header.Get("Location"), nil
}

// Authorization returns the authorization object associated with
// the given authorization URI.
func (c *Client) Authorization(authURI string) (Authorization, error) {
	var auth Authorization
	resp, err := c.client.Get(authURI)
	if err != nil {
		return auth, err
	}
	defer resp.Body.Close()
	if err = checkHTTPError(resp, http.StatusOK); err != nil {
		return auth, err
	}

	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		return auth, fmt.Errorf("decoding response body: %v", err)
	}
	return auth, nil
}

// Challenge returns the challenge object associated with the
// given challenge URI.
func (c *Client) Challenge(chalURI string) (Challenge, error) {
	var chal Challenge
	resp, err := c.client.Get(chalURI)
	if err != nil {
		return chal, err
	}
	defer resp.Body.Close()
	if err = checkHTTPError(resp, http.StatusAccepted); err != nil {
		return chal, err
	}

	if err := json.NewDecoder(resp.Body).Decode(&chal); err != nil {
		return chal, fmt.Errorf("decoding response body: %v", err)
	}
	return chal, nil
}

// NewCertificate requests a certificate from the ACME server.
//
// csr must have already been signed by a private key.
func (c *Client) NewCertificate(accountKey interface{}, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if csr == nil || csr.Raw == nil {
		return nil, errors.New("invalid certificate request object")
	}
	payload := struct {
		Resource string `json:"resource"`
		CSR      string `json:"csr"`
	}{
		resourceNewCertificate,
		base64.RawURLEncoding.EncodeToString(csr.Raw),
	}
	data, err := c.signObject(accountKey, &payload)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Post(c.resources.NewCertificate, jwsContentType, strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkHTTPError(resp, http.StatusCreated); err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %v", err)
	}
	return x509.ParseCertificate(body)
}

// TODO: doesn't need to be a function on the client struct
func (c *Client) signObject(accountKey interface{}, v interface{}) (string, error) {
	var (
		signer jose.Signer
		err    error
	)
	switch accountKey := accountKey.(type) {
	case *rsa.PrivateKey:
		signer, err = jose.NewSigner(jose.RS256, accountKey)
	case *ecdsa.PrivateKey:
		signer, err = jose.NewSigner(jose.ES384, accountKey)
	default:
		err = errors.New("acme: unsupported private key type")
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	signer.SetNonceSource(c.nonceSource)
	sig, err := signer.Sign(data)
	if err != nil {
		return "", err
	}
	return sig.FullSerialize(), nil
}

var linkRegexp = regexp.MustCompile(`<([^>]+)>\s*;\s*rel\s*=\s*"([A-Za-z0-9\-_]+)"`)

func parseLink(link string) (url, rel string, err error) {
	match := linkRegexp.FindStringSubmatch(link)
	if match == nil || len(match) != 3 {
		err = fmt.Errorf("invalid link: %s", link)
	} else {
		url = match[1]
		rel = match[2]
	}
	return
}
