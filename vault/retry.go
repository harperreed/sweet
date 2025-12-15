// ABOUTME: Retry logic with exponential backoff for sync operations.
// ABOUTME: Handles transient network failures with configurable retry behavior.
package vault

import (
	"context"
	"errors"
	"time"
)

// RetryConfig controls retry behavior.
type RetryConfig struct {
	MaxAttempts int           // maximum number of attempts (default: 3)
	InitialWait time.Duration // wait before first retry (default: 500ms)
	MaxWait     time.Duration // maximum wait between retries (default: 30s)
	Multiplier  float64       // backoff multiplier (default: 2.0)
}

// DefaultRetryConfig returns sensible defaults.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		InitialWait: 500 * time.Millisecond,
		MaxWait:     30 * time.Second,
		Multiplier:  2.0,
	}
}

// Retryable returns true if the error should trigger a retry.
// Network failures and server errors are retryable; auth errors are not.
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNetworkFailure) || errors.Is(err, ErrServerError) {
		return true
	}
	return false
}

// WithRetry executes fn with retry logic.
// Returns result on success, or SyncError after exhausting retries.
func WithRetry[T any](ctx context.Context, cfg RetryConfig, op string, fn func() (T, error)) (T, error) {
	var zero T
	wait := cfg.InitialWait
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 1
	}

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		result, err := fn()
		if err == nil {
			return result, nil
		}

		// Don't retry non-retryable errors
		if !Retryable(err) || attempt == cfg.MaxAttempts {
			return zero, &SyncError{Op: op, Err: err, Retries: attempt}
		}

		// Wait before retry, respecting context cancellation
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(wait):
		}

		// Increase wait time with backoff
		wait = time.Duration(float64(wait) * cfg.Multiplier)
		if cfg.MaxWait > 0 && wait > cfg.MaxWait {
			wait = cfg.MaxWait
		}
	}

	return zero, &SyncError{Op: op, Err: ErrNetworkFailure, Retries: cfg.MaxAttempts}
}
