// ABOUTME: Unit tests for rate limiter configuration and behavior.
// ABOUTME: Validates handling of zero/negative intervals and disabled state.

package main

import (
	"testing"
	"time"
)

func TestRateLimiterZeroInterval(t *testing.T) {
	// Zero interval should disable rate limiting (unlimited rate)
	store := newRateLimiterStore(RateLimitConfig{Interval: 0, Burst: 100})
	limiter := store.get("user-1")

	// Should allow rapid requests without blocking
	for i := 0; i < 1000; i++ {
		if !limiter.Allow() {
			t.Fatalf("zero interval limiter blocked request %d (should be unlimited)", i)
		}
	}
}

func TestRateLimiterNegativeInterval(t *testing.T) {
	// Negative interval should disable rate limiting (unlimited rate)
	store := newRateLimiterStore(RateLimitConfig{Interval: -1 * time.Second, Burst: 100})
	limiter := store.get("user-2")

	// Should allow rapid requests without blocking
	for i := 0; i < 1000; i++ {
		if !limiter.Allow() {
			t.Fatalf("negative interval limiter blocked request %d (should be unlimited)", i)
		}
	}
}

func TestRateLimiterSetConfigZeroInterval(t *testing.T) {
	// Start with normal rate limit
	store := newRateLimiterStore(RateLimitConfig{Interval: time.Second, Burst: 1})
	limiter := store.get("user-3")

	// First request succeeds
	if !limiter.Allow() {
		t.Fatal("first request should succeed")
	}

	// Second immediate request should fail (rate limited)
	if limiter.Allow() {
		t.Fatal("second immediate request should be rate limited")
	}

	// Now disable rate limiting
	store.setConfig(0, 1000)

	// Get new limiter for same user (old one was cleared)
	limiter = store.get("user-3")

	// Should allow rapid requests now
	for i := 0; i < 100; i++ {
		if !limiter.Allow() {
			t.Fatalf("after setting zero interval, request %d should succeed", i)
		}
	}
}

func TestRateLimiterNormalBehavior(t *testing.T) {
	// Ensure normal rate limiting still works
	store := newRateLimiterStore(RateLimitConfig{Interval: 100 * time.Millisecond, Burst: 2})
	limiter := store.get("user-4")

	// Burst of 2 should succeed
	if !limiter.Allow() {
		t.Fatal("request 1 should succeed")
	}
	if !limiter.Allow() {
		t.Fatal("request 2 should succeed")
	}

	// Third immediate request should fail
	if limiter.Allow() {
		t.Fatal("request 3 should be rate limited")
	}

	// Wait for token replenishment
	time.Sleep(110 * time.Millisecond)

	// Should work again
	if !limiter.Allow() {
		t.Fatal("request after waiting should succeed")
	}
}

func TestRateLimiterPerUser(t *testing.T) {
	// Verify rate limiting is per-user
	store := newRateLimiterStore(RateLimitConfig{Interval: time.Second, Burst: 1})

	limiter1 := store.get("user-a")
	limiter2 := store.get("user-b")

	// Each user gets their own limiter
	if !limiter1.Allow() {
		t.Fatal("user-a first request should succeed")
	}
	if !limiter2.Allow() {
		t.Fatal("user-b first request should succeed")
	}

	// Second requests should both fail (different limiters)
	if limiter1.Allow() {
		t.Fatal("user-a second request should be rate limited")
	}
	if limiter2.Allow() {
		t.Fatal("user-b second request should be rate limited")
	}
}

func TestDefaultRateLimitConfig(t *testing.T) {
	// Verify default config is sensible
	config := DefaultRateLimitConfig()
	if config.Interval <= 0 {
		t.Errorf("default interval should be positive, got %v", config.Interval)
	}
	if config.Burst <= 0 {
		t.Errorf("default burst should be positive, got %d", config.Burst)
	}
}

func TestRateLimiterDisabledForTesting(t *testing.T) {
	// This test validates the pattern used in TestSnapshotAndPrune
	// where rate limiting is disabled via setRateLimit(0, 1000)
	store := newRateLimiterStore(DefaultRateLimitConfig())

	// Start with normal rate limiting
	limiter := store.get("test-user")
	if !limiter.Allow() {
		t.Fatal("first request should succeed")
	}
	if !limiter.Allow() {
		t.Fatal("second request within burst should succeed")
	}

	// Disable rate limiting (pattern from TestSnapshotAndPrune)
	store.setConfig(0, 1000)

	// Get fresh limiter
	limiter = store.get("test-user")

	// Should allow unlimited requests
	for i := 0; i < 1000; i++ {
		if !limiter.Allow() {
			t.Fatalf("request %d should succeed when rate limiting disabled", i)
		}
	}
}
