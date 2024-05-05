package v4

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Signer struct {
	accountID     string
	rsaPrivateKey *rsa.PrivateKey
}

func New(accountID string, privateKey []byte) (*Signer, error) {
	key, err := parseKey(privateKey)
	if err != nil {
		return nil, err
	}

	return &Signer{
		accountID:     accountID,
		rsaPrivateKey: key,
	}, nil
}

func NewWithJSONFile(json_file []byte) (*Signer, error) {
	service_account := map[string]string{}
	if err := json.Unmarshal(json_file, &service_account); err != nil {
		return nil, err
	}

	return New(service_account["client_email"], []byte(service_account["private_key"]))
}

func (s *Signer) GetSignedURL(method, path string, expires time.Time) (string, error) {
	now := time.Now().UTC()

	u := &url.URL{
		Host:    "storage.googleapis.com",
		Scheme:  "https",
		Path:    path,
		RawPath: pathEncodeV4(path),
	}

	timestamp := now.Format(iso8601)
	credentialScope := fmt.Sprintf("%s/auto/storage/goog4_request", now.Format(yearMonthDay))
	canonicalQueryString := url.Values{
		"X-Goog-Algorithm":     {"GOOG4-RSA-SHA256"},
		"X-Goog-Credential":    {fmt.Sprintf("%s/%s", s.accountID, credentialScope)},
		"X-Goog-Date":          {timestamp},
		"X-Goog-Expires":       {fmt.Sprintf("%d", int(expires.Sub(now).Seconds()))},
		"X-Goog-SignedHeaders": {"host"},
	}

	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "%s\n", method)
	fmt.Fprintf(buf, "/%s\n", u.RawPath)
	fmt.Fprintf(buf, "%s\n", strings.Replace(canonicalQueryString.Encode(), "+", "%20", -1))
	fmt.Fprintf(buf, "%s\n\n", "host:"+u.Hostname())
	fmt.Fprintf(buf, "%s\n", "host")
	fmt.Fprint(buf, "UNSIGNED-PAYLOAD")

	sum := sha256.Sum256(buf.Bytes())
	hexDigest := hex.EncodeToString(sum[:])

	signBuf := &bytes.Buffer{}
	fmt.Fprintf(signBuf,
		"GOOG4-RSA-SHA256\n%s\n%s\n%s",
		timestamp,
		credentialScope,
		hexDigest,
	)

	b, err := signBytes(signBuf.Bytes(), s.rsaPrivateKey)
	if err != nil {
		return "", err
	}

	signature := hex.EncodeToString(b)
	canonicalQueryString.Set("X-Goog-Signature", string(signature))
	u.RawQuery = canonicalQueryString.Encode()

	return u.String(), nil
}

func parseKey(key []byte) (*rsa.PrivateKey, error) {
	if block, _ := pem.Decode(key); block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return nil, err
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("oauth2: private key is invalid")
	}
	return parsed, nil
}

func signBytes(b []byte, key *rsa.PrivateKey) ([]byte, error) {
	sum := sha256.Sum256(b)
	return rsa.SignPKCS1v15(
		rand.Reader,
		key,
		crypto.SHA256,
		sum[:],
	)
}

func pathEncodeV4(path string) string {
	segments := strings.Split(path, "/")
	var encodedSegments []string
	for _, s := range segments {
		encodedSegments = append(encodedSegments, url.QueryEscape(s))
	}
	encodedStr := strings.Join(encodedSegments, "/")
	encodedStr = strings.Replace(encodedStr, "+", "%20", -1)
	return encodedStr
}

const (
	iso8601      = "20060102T150405Z"
	yearMonthDay = "20060102"
)
