// ABOUTME: Tests for getClientIP function and proxy header security.
// ABOUTME: Validates that proxy headers are only trusted when TRUSTED_PROXY=1.

package main

import (
	"net/http"
	"os"
	"testing"
)

func TestGetClientIP_WithoutTrustedProxy(t *testing.T) {
	tests := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		xRealIP       string
		expectedIP    string
	}{
		{
			name:          "ignores X-Forwarded-For when not trusted",
			remoteAddr:    "192.168.1.100:1234",
			xForwardedFor: "10.0.0.1",
			expectedIP:    "192.168.1.100",
		},
		{
			name:       "ignores X-Real-IP when not trusted",
			remoteAddr: "192.168.1.100:1234",
			xRealIP:    "10.0.0.1",
			expectedIP: "192.168.1.100",
		},
		{
			name:       "uses RemoteAddr when no proxy headers",
			remoteAddr: "203.0.113.42:5678",
			expectedIP: "203.0.113.42",
		},
		{
			name:          "ignores spoofed headers",
			remoteAddr:    "192.168.1.100:1234",
			xForwardedFor: "1.2.3.4, 5.6.7.8",
			xRealIP:       "9.10.11.12",
			expectedIP:    "192.168.1.100",
		},
		{
			name:          "handles RemoteAddr without port",
			remoteAddr:    "192.168.1.100",
			xForwardedFor: "10.0.0.1",
			expectedIP:    "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure TRUSTED_PROXY is not set for this specific test
			oldValue := os.Getenv("TRUSTED_PROXY")
			os.Unsetenv("TRUSTED_PROXY")
			defer func() {
				if oldValue != "" {
					os.Setenv("TRUSTED_PROXY", oldValue)
				}
			}()

			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     http.Header{},
			}

			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			got := getClientIP(req)
			if got != tt.expectedIP {
				t.Errorf("getClientIP() = %v, want %v (TRUSTED_PROXY='%s')", got, tt.expectedIP, os.Getenv("TRUSTED_PROXY"))
			}
		})
	}
}

func TestGetClientIP_WithTrustedProxy(t *testing.T) {
	tests := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		xRealIP       string
		expectedIP    string
	}{
		{
			name:          "trusts X-Forwarded-For when TRUSTED_PROXY=1",
			remoteAddr:    "192.168.1.100:1234",
			xForwardedFor: "10.0.0.1",
			expectedIP:    "10.0.0.1",
		},
		{
			name:       "trusts X-Real-IP when TRUSTED_PROXY=1",
			remoteAddr: "192.168.1.100:1234",
			xRealIP:    "10.0.0.1",
			expectedIP: "10.0.0.1",
		},
		{
			name:          "prefers X-Forwarded-For over X-Real-IP",
			remoteAddr:    "192.168.1.100:1234",
			xForwardedFor: "10.0.0.1",
			xRealIP:       "10.0.0.2",
			expectedIP:    "10.0.0.1",
		},
		{
			name:          "extracts first IP from X-Forwarded-For chain",
			remoteAddr:    "192.168.1.100:1234",
			xForwardedFor: "1.2.3.4, 5.6.7.8, 9.10.11.12",
			expectedIP:    "1.2.3.4",
		},
		{
			name:       "falls back to RemoteAddr when no proxy headers",
			remoteAddr: "203.0.113.42:5678",
			expectedIP: "203.0.113.42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set TRUSTED_PROXY for this specific test
			oldValue := os.Getenv("TRUSTED_PROXY")
			os.Setenv("TRUSTED_PROXY", "1")
			defer func() {
				if oldValue != "" {
					os.Setenv("TRUSTED_PROXY", oldValue)
				} else {
					os.Unsetenv("TRUSTED_PROXY")
				}
			}()

			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     http.Header{},
			}

			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			got := getClientIP(req)
			if got != tt.expectedIP {
				t.Errorf("getClientIP() = %v, want %v", got, tt.expectedIP)
			}
		})
	}
}

func TestGetClientIP_DifferentProxyValues(t *testing.T) {
	// Test that only "1" is trusted
	tests := []struct {
		name        string
		proxyValue  string
		shouldTrust bool
	}{
		{
			name:        "trusts value '1'",
			proxyValue:  "1",
			shouldTrust: true,
		},
		{
			name:        "does not trust 'true'",
			proxyValue:  "true",
			shouldTrust: false,
		},
		{
			name:        "does not trust 'yes'",
			proxyValue:  "yes",
			shouldTrust: false,
		},
		{
			name:        "does not trust empty string",
			proxyValue:  "",
			shouldTrust: false,
		},
		{
			name:        "does not trust '0'",
			proxyValue:  "0",
			shouldTrust: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.proxyValue == "" {
				os.Unsetenv("TRUSTED_PROXY")
			} else {
				os.Setenv("TRUSTED_PROXY", tt.proxyValue)
			}
			defer os.Unsetenv("TRUSTED_PROXY")

			req := &http.Request{
				RemoteAddr: "192.168.1.100:1234",
				Header:     http.Header{},
			}
			req.Header.Set("X-Forwarded-For", "10.0.0.1")

			got := getClientIP(req)

			if tt.shouldTrust {
				// Should use X-Forwarded-For
				if got != "10.0.0.1" {
					t.Errorf("expected to trust proxy header and get 10.0.0.1, got %v", got)
				}
			} else {
				// Should use RemoteAddr
				if got != "192.168.1.100" {
					t.Errorf("expected to not trust proxy header and get 192.168.1.100, got %v", got)
				}
			}
		})
	}
}
