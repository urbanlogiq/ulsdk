// Copyright (c), CommunityLogiq Software

package ulsdk

import (
	"bytes"
	"fmt"
	"os"

	"github.com/google/uuid"
)

// TestContext wraps an ApiKeyContext and returns canned responses for testing.
// GET and DELETE requests are forwarded to /v1/echo/ to validate signing.
// POST and PUT requests send the canned response to /v1/echo/ and verify
// the echo matches, ensuring round-trip serialization correctness.
type TestContext struct {
	context  *ApiKeyContext
	response []byte
}

// NewTestContextFromEnv creates a TestContext using credentials from the
// CA_USER, CA_ACCESS_KEY, and CA_SECRET_KEY environment variables. It returns
// nil if any of the variables are unset, allowing callers to skip the test.
func NewTestContextFromEnv() *TestContext {
	user := os.Getenv("CA_USER")
	accessKey := os.Getenv("CA_ACCESS_KEY")
	secretKey := os.Getenv("CA_SECRET_KEY")
	if user == "" || accessKey == "" || secretKey == "" {
		return nil
	}
	userID, err := uuid.Parse(user)
	if err != nil {
		return nil
	}
	key := &Key{
		UserID:    userID,
		Region:    RegionCA,
		AccessKey: accessKey,
		SecretKey: secretKey,
	}
	keyCtx := NewApiKeyContext(key, EnvironmentStage)
	return NewTestContext(keyCtx)
}

// NewTestContext creates a new TestContext wrapping the given ApiKeyContext.
func NewTestContext(context *ApiKeyContext) *TestContext {
	return &TestContext{
		context:  context,
		response: []byte{},
	}
}

// SetResponse sets the canned response that will be returned by all requests.
func (c *TestContext) SetResponse(response []byte) {
	c.response = response
}

// Get makes an authenticated GET to /v1/echo/ and returns the canned response.
func (c *TestContext) Get(path string, params [][2]string, headers map[string]string) ([]byte, error) {
	_, err := c.context.Get("/v1/echo/", params, headers)
	if err != nil {
		return nil, err
	}
	return c.response, nil
}

// Post sends the canned response to /v1/echo/ and verifies the echo matches.
func (c *TestContext) Post(path string, body []byte, contentType string, params [][2]string, headers map[string]string) ([]byte, error) {
	r, err := c.context.Post("/v1/echo/", c.response, contentType, params, headers)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r, c.response) {
		return nil, fmt.Errorf("test failure, expected response to match request")
	}
	return c.response, nil
}

// Put sends the canned response to /v1/echo/ and verifies the echo matches.
func (c *TestContext) Put(path string, body []byte, contentType string, params [][2]string, headers map[string]string) ([]byte, error) {
	r, err := c.context.Put("/v1/echo/", c.response, contentType, params, headers)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r, c.response) {
		return nil, fmt.Errorf("test failure, expected response to match request")
	}
	return c.response, nil
}

// Delete makes an authenticated DELETE to /v1/echo/ and returns the canned response.
func (c *TestContext) Delete(path string, params [][2]string, headers map[string]string) ([]byte, error) {
	_, err := c.context.Delete("/v1/echo/", params, headers)
	if err != nil {
		return nil, err
	}
	return c.response, nil
}
