// Copyright (c), CommunityLogiq Software

package ulsdk

import (
	"testing"
)

func TestCanonicalizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/v1/api/foo", "/v1/api/foo"},
		{"v1/api/foo", "/v1/api/foo"},
		{"/", "/"},
		{"", "/"},
	}
	for _, tt := range tests {
		got := canonicalizePath(tt.input)
		if got != tt.want {
			t.Errorf("canonicalizePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCanonicalizeQueryString(t *testing.T) {
	tests := []struct {
		input [][2]string
		want  string
	}{
		{nil, ""},
		{[][2]string{}, ""},
		{[][2]string{{"b", "2"}, {"a", "1"}}, "a=1&b=2"},
		{[][2]string{{"X-UL-Signature", "sig"}, {"a", "1"}}, "a=1"},
		{[][2]string{{"key", "hello world"}}, "key=hello+world"},
	}
	for _, tt := range tests {
		got := canonicalizeQueryString(tt.input)
		if got != tt.want {
			t.Errorf("canonicalizeQueryString(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCanonicalizeHeaders(t *testing.T) {
	headers := map[string]string{
		"x-ul-date": "1234567890",
	}
	got := canonicalizeHeaders([]string{"x-ul-date"}, headers)
	want := "x-ul-date:1234567890"
	if got != want {
		t.Errorf("canonicalizeHeaders = %q, want %q", got, want)
	}
}

func TestHashBytes(t *testing.T) {
	got := hashBytes([]byte(""))
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("hashBytes(empty) = %q, want %q", got, want)
	}
}

func TestParseKeysFile(t *testing.T) {
	content := `[default]
user_id = 00000000-0000-0000-0000-000000000001
region = ca
access_key = myaccesskey
secret_key = bXlzZWNyZXRrZXkwMTIzNDU2Nzg5YWJjZGVm

[other]
user_id = 00000000-0000-0000-0000-000000000002
region = us
access_key = otheraccesskey
secret_key = b3RoZXJzZWNyZXRrZXkwMTIzNDU2Nzg5YQ
`

	key, err := parseKeysFile(content, "default")
	if err != nil {
		t.Fatalf("parseKeysFile failed: %v", err)
	}
	if key.AccessKey != "myaccesskey" {
		t.Errorf("AccessKey = %q, want %q", key.AccessKey, "myaccesskey")
	}
	if key.Region != RegionCA {
		t.Errorf("Region = %v, want CA", key.Region)
	}
	if key.UserID.String() != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("UserID = %v, want 00000000-0000-0000-0000-000000000001", key.UserID)
	}

	key2, err := parseKeysFile(content, "other")
	if err != nil {
		t.Fatalf("parseKeysFile(other) failed: %v", err)
	}
	if key2.Region != RegionUS {
		t.Errorf("Region = %v, want US", key2.Region)
	}

	_, err = parseKeysFile(content, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestGetEndpoint(t *testing.T) {
	tests := []struct {
		region Region
		env    Environment
		path   string
		want   string
	}{
		{RegionCA, EnvironmentProd, "/v1/api/foo", "https://api.urbanlogiq.ca/v1/api/foo"},
		{RegionCA, EnvironmentStage, "/v1/api/foo", "https://stage.urbanlogiq.ca/v1/api/foo"},
		{RegionUS, EnvironmentProd, "/v1/api/foo", "https://api.urbanlogiq.us/v1/api/foo"},
		{RegionUS, EnvironmentStage, "/v1/api/foo", "https://stage.urbanlogiq.us/v1/api/foo"},
	}
	for _, tt := range tests {
		got := GetEndpoint(tt.region, tt.env, tt.path)
		if got != tt.want {
			t.Errorf("GetEndpoint(%v, %v, %q) = %q, want %q", tt.region, tt.env, tt.path, got, tt.want)
		}
	}
}
