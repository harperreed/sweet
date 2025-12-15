// ABOUTME: Tests for retry with exponential backoff.
// ABOUTME: Verifies retry behavior, backoff timing, and error classification.
package vault

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDefaultRetryConfig(t *testing.T) {
	cfg := DefaultRetryConfig()

	if cfg.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", cfg.MaxAttempts)
	}
	if cfg.InitialWait != 500*time.Millisecond {
		t.Errorf("InitialWait = %v, want 500ms", cfg.InitialWait)
	}
	if cfg.MaxWait != 30*time.Second {
		t.Errorf("MaxWait = %v, want 30s", cfg.MaxWait)
	}
	if cfg.Multiplier != 2.0 {
		t.Errorf("Multiplier = %v, want 2.0", cfg.Multiplier)
	}
}

func TestRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"network failure", ErrNetworkFailure, true},
		{"server error", ErrServerError, true},
		{"token expired", ErrTokenExpired, false},
		{"unauthorized", ErrUnauthorized, false},
		{"wrapped network", &SyncError{Err: ErrNetworkFailure}, true},
		{"wrapped token", &SyncError{Err: ErrTokenExpired}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Retryable(tt.err)
			if got != tt.want {
				t.Errorf("Retryable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestWithRetry_SuccessFirstAttempt(t *testing.T) {
	cfg := RetryConfig{MaxAttempts: 3, InitialWait: time.Millisecond}
	attempts := 0

	result, err := WithRetry(context.Background(), cfg, "test", func() (string, error) {
		attempts++
		return "success", nil
	})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != "success" {
		t.Errorf("result = %q, want %q", result, "success")
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
}

func TestWithRetry_SuccessAfterRetries(t *testing.T) {
	cfg := RetryConfig{MaxAttempts: 3, InitialWait: time.Millisecond, Multiplier: 1.0}
	attempts := 0

	result, err := WithRetry(context.Background(), cfg, "test", func() (string, error) {
		attempts++
		if attempts < 3 {
			return "", ErrNetworkFailure
		}
		return "success", nil
	})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != "success" {
		t.Errorf("result = %q, want %q", result, "success")
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestWithRetry_ExhaustedRetries(t *testing.T) {
	cfg := RetryConfig{MaxAttempts: 3, InitialWait: time.Millisecond, Multiplier: 1.0}
	attempts := 0

	_, err := WithRetry(context.Background(), cfg, "push", func() (string, error) {
		attempts++
		return "", ErrNetworkFailure
	})

	if err == nil {
		t.Fatal("expected error after exhausted retries")
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}

	var syncErr *SyncError
	if !errors.As(err, &syncErr) {
		t.Fatal("expected *SyncError")
	}
	if syncErr.Op != "push" {
		t.Errorf("Op = %q, want %q", syncErr.Op, "push")
	}
	if syncErr.Retries != 3 {
		t.Errorf("Retries = %d, want 3", syncErr.Retries)
	}
}

func TestWithRetry_NonRetryableError(t *testing.T) {
	cfg := RetryConfig{MaxAttempts: 3, InitialWait: time.Millisecond}
	attempts := 0

	_, err := WithRetry(context.Background(), cfg, "refresh", func() (string, error) {
		attempts++
		return "", ErrTokenExpired
	})

	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (should not retry non-retryable)", attempts)
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestWithRetry_ContextCanceled(t *testing.T) {
	cfg := RetryConfig{MaxAttempts: 5, InitialWait: 100 * time.Millisecond, Multiplier: 1.0}
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := WithRetry(ctx, cfg, "test", func() (string, error) {
		attempts++
		return "", ErrNetworkFailure
	})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}
