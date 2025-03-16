package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey valid-api-key-123")

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if apiKey != "valid-api-key-123" {
		t.Fatalf("expected API key to be 'valid-api-key-123', got '%s'", apiKey)
	}
}

func TestGetAPIKey_MissingHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected error to be 'ErrNoAuthHeaderIncluded', got '%v'", err)
	}
}

func TestGetAPIKey_MalformedHeader_MissingPrefix(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer invalid-api-key") // Invalid prefix, should be ApiKey

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err.Error() != "malformed authorization header" {
		t.Fatalf("expected error to be 'malformed authorization header', got '%v'", err)
	}
}

func TestGetAPIKey_MalformedHeader_MissingKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey") // Missing key part

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err.Error() != "malformed authorization header" {
		t.Fatalf("expected error to be 'malformed authorization header', got '%v'", err)
	}
}

func TestGetAPIKey_EmptyHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "") // Empty header value

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected error to be 'ErrNoAuthHeaderIncluded', got '%v'", err)
	}
}
