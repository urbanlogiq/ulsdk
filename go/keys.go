// Copyright (c), CommunityLogiq Software

package ulsdk

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// Region represents an UrbanLogiq deployment region.
type Region int

const (
	RegionCA Region = iota
	RegionUS
)

func (r Region) String() string {
	switch r {
	case RegionCA:
		return "ca"
	case RegionUS:
		return "us"
	default:
		return "unknown"
	}
}

// ParseRegion parses a region string ("ca", "us") into a Region.
func ParseRegion(s string) (Region, error) {
	switch strings.ToLower(s) {
	case "ca":
		return RegionCA, nil
	case "us":
		return RegionUS, nil
	default:
		return 0, fmt.Errorf("unknown region: %s", s)
	}
}

// Environment represents an UrbanLogiq deployment environment.
type Environment int

const (
	EnvironmentProd Environment = iota
	EnvironmentStage
)

func (e Environment) String() string {
	switch e {
	case EnvironmentProd:
		return "prod"
	case EnvironmentStage:
		return "stage"
	default:
		return "unknown"
	}
}

// ParseEnvironment parses an environment string ("prod", "stage") into an Environment.
func ParseEnvironment(s string) (Environment, error) {
	switch strings.ToLower(s) {
	case "prod":
		return EnvironmentProd, nil
	case "stage":
		return EnvironmentStage, nil
	default:
		return 0, fmt.Errorf("unknown environment: %s", s)
	}
}

// Key holds the credentials for authenticating API requests.
type Key struct {
	UserID    uuid.UUID
	Region    Region
	AccessKey string
	SecretKey string
}

// GetEndpoint returns the base URL for the given region and environment.
func GetEndpoint(region Region, environment Environment, path string) string {
	var base string
	switch {
	case region == RegionCA && environment == EnvironmentProd:
		base = "https://api.urbanlogiq.ca"
	case region == RegionCA && environment == EnvironmentStage:
		base = "https://stage.urbanlogiq.ca"
	case region == RegionUS && environment == EnvironmentProd:
		base = "https://api.urbanlogiq.us"
	case region == RegionUS && environment == EnvironmentStage:
		base = "https://stage.urbanlogiq.us"
	default:
		base = "https://api.urbanlogiq.ca"
	}
	return base + path
}

// LoadKey loads a key from the ~/.ul/keys file for the given profile.
// The file uses INI-style format with sections as profile names.
func LoadKey(profile string) (*Key, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	keysPath := filepath.Join(home, ".ul", "keys")
	data, err := os.ReadFile(keysPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keys file: %w", err)
	}

	return parseKeysFile(string(data), profile)
}

func parseKeysFile(content string, profile string) (*Key, error) {
	lines := strings.Split(content, "\n")
	sectionTarget := "[" + profile + "]"

	inSection := false
	values := make(map[string]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inSection = line == sectionTarget
			continue
		}
		if inSection {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				values[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	if len(values) == 0 {
		return nil, fmt.Errorf("profile '%s' not found in keys file", profile)
	}

	userIDStr, ok := values["user_id"]
	if !ok {
		return nil, fmt.Errorf("profile '%s' missing user_id", profile)
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user_id: %w", err)
	}

	regionStr, ok := values["region"]
	if !ok {
		return nil, fmt.Errorf("profile '%s' missing region", profile)
	}
	region, err := ParseRegion(regionStr)
	if err != nil {
		return nil, err
	}

	accessKey, ok := values["access_key"]
	if !ok {
		return nil, fmt.Errorf("profile '%s' missing access_key", profile)
	}

	secretKey, ok := values["secret_key"]
	if !ok {
		return nil, fmt.Errorf("profile '%s' missing secret_key", profile)
	}

	return &Key{
		UserID:    userID,
		Region:    region,
		AccessKey: accessKey,
		SecretKey: secretKey,
	}, nil
}
