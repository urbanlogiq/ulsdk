// Copyright (c), CommunityLogiq Software

package ulsdk

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	requestType = "ul1_request"
	signatureV1 = "UL1-ED25519"
)

// ApiKeyContext implements the api.RequestContext interface using ED25519-signed
// API key authentication.
type ApiKeyContext struct {
	key         *Key
	environment Environment
	client      *http.Client
}

// NewApiKeyContext creates a new ApiKeyContext with the given key and environment.
func NewApiKeyContext(key *Key, environment Environment) *ApiKeyContext {
	return &ApiKeyContext{
		key:         key,
		environment: environment,
		client:      &http.Client{},
	}
}

func canonicalizePath(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func canonicalizeQueryString(params [][2]string) string {
	if len(params) == 0 {
		return ""
	}

	var components []string
	for _, p := range params {
		if p[0] == "X-UL-Signature" {
			continue
		}
		components = append(components, p[0]+"="+url.QueryEscape(p[1]))
	}
	sort.Strings(components)
	return strings.Join(components, "&")
}

func canonicalizeHeaders(signedHeaders []string, headers map[string]string) string {
	sorted := make([]string, len(signedHeaders))
	copy(sorted, signedHeaders)
	sort.Strings(sorted)

	var parts []string
	for _, h := range sorted {
		parts = append(parts, strings.ToLower(h)+":"+strings.TrimSpace(headers[h]))
	}
	return strings.Join(parts, "\n")
}

func hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

func canonicalizeRequest(
	method string,
	path string,
	params [][2]string,
	headers map[string]string,
	signedHeaders []string,
	body []byte,
) string {
	canonicalPath := canonicalizePath(path)
	canonicalQuery := canonicalizeQueryString(params)
	canonicalHdrs := canonicalizeHeaders(signedHeaders, headers)

	sorted := make([]string, len(signedHeaders))
	copy(sorted, signedHeaders)
	sort.Strings(sorted)

	s := method + "\n" +
		canonicalPath + "\n" +
		canonicalQuery + "\n" +
		canonicalHdrs + "\n" +
		strings.Join(sorted, ";") + "\n" +
		hashBytes(body)

	return hashBytes([]byte(s))
}

func generateAuthHeader(
	key *Key,
	method string,
	path string,
	params [][2]string,
	headers map[string]string,
	body []byte,
) {
	ts := time.Now().Unix()
	signedHeaders := []string{"x-ul-date"}
	headers["x-ul-date"] = fmt.Sprintf("%d", ts)

	requestHash := canonicalizeRequest(method, path, params, headers, signedHeaders, body)
	scope := fmt.Sprintf("%s/%d/%s/%s", key.UserID, ts, key.Region, requestType)

	signingString := signatureV1 + "\n" + scope + "\n" + requestHash

	// Decode the base64-encoded secret key (with padding)
	secretKeyBytes, err := base64.StdEncoding.DecodeString(key.SecretKey + "==")
	if err != nil {
		// Try without extra padding
		secretKeyBytes, _ = base64.StdEncoding.DecodeString(key.SecretKey)
	}

	// Use the first 32 bytes as the ED25519 seed
	seed := secretKeyBytes[:32]
	privateKey := ed25519.NewKeyFromSeed(seed)
	signature := ed25519.Sign(privateKey, []byte(signingString))

	authHeader := fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%x",
		signatureV1,
		key.AccessKey,
		scope,
		strings.Join(signedHeaders, ";"),
		signature,
	)
	headers["authorization"] = authHeader
}

func (c *ApiKeyContext) doRequest(method, path string, body []byte, contentType string, params [][2]string, headers map[string]string) ([]byte, error) {
	// Merge caller-provided headers into a mutable copy
	mergedHeaders := make(map[string]string)
	for k, v := range headers {
		mergedHeaders[k] = v
	}

	if contentType != "" {
		mergedHeaders["content-type"] = contentType
	}

	generateAuthHeader(c.key, method, path, params, mergedHeaders, body)

	endpoint := GetEndpoint(c.key.Region, c.environment, path)

	// Append query parameters
	if len(params) > 0 {
		q := url.Values{}
		for _, p := range params {
			q.Add(p[0], p[1])
		}
		endpoint = endpoint + "?" + q.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = strings.NewReader(string(body))
	}

	req, err := http.NewRequest(method, endpoint, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range mergedHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// Get makes an authenticated GET request.
func (c *ApiKeyContext) Get(path string, params [][2]string, headers map[string]string) ([]byte, error) {
	return c.doRequest("GET", path, nil, "", params, headers)
}

// Post makes an authenticated POST request.
func (c *ApiKeyContext) Post(path string, body []byte, contentType string, params [][2]string, headers map[string]string) ([]byte, error) {
	return c.doRequest("POST", path, body, contentType, params, headers)
}

// Put makes an authenticated PUT request.
func (c *ApiKeyContext) Put(path string, body []byte, contentType string, params [][2]string, headers map[string]string) ([]byte, error) {
	return c.doRequest("PUT", path, body, contentType, params, headers)
}

// Delete makes an authenticated DELETE request.
func (c *ApiKeyContext) Delete(path string, params [][2]string, headers map[string]string) ([]byte, error) {
	return c.doRequest("DELETE", path, nil, "", params, headers)
}
