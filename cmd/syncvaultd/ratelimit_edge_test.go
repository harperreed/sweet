// ABOUTME: Edge case tests for rate limiter behavior with zero/negative intervals.
// ABOUTME: Validates actual rate.Limiter behavior when constructed with Every(0).

package main

import (
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestRateEveryZeroBehavior(t *testing.T) {
	// Document actual behavior of rate.Every(0)
	limit := rate.Every(0)
	t.Logf("rate.Every(0) = %v", limit)

	limiter := rate.NewLimiter(limit, 100)

	// Test if it's effectively unlimited
	allowed := 0
	for i := 0; i < 10000; i++ {
		if limiter.Allow() {
			allowed++
		}
	}

	t.Logf("Allowed %d out of 10000 requests with rate.Every(0)", allowed)

	// rate.Every(0) should result in rate.Inf (unlimited)
	if allowed != 10000 {
		t.Errorf("Expected all 10000 requests to be allowed with zero interval, got %d", allowed)
	}
}

func TestRateEveryNegativeBehavior(t *testing.T) {
	// Document behavior with negative duration
	limit := rate.Every(-1 * time.Second)
	t.Logf("rate.Every(-1s) = %v", limit)

	limiter := rate.NewLimiter(limit, 100)

	// Test if it's effectively unlimited
	allowed := 0
	for i := 0; i < 10000; i++ {
		if limiter.Allow() {
			allowed++
		}
	}

	t.Logf("Allowed %d out of 10000 requests with negative interval", allowed)

	// With negative duration, behavior should be unlimited (negative rate -> Inf)
	if allowed != 10000 {
		t.Errorf("Expected all 10000 requests to be allowed with negative interval, got %d", allowed)
	}
}

func TestExplicitInfiniteRate(t *testing.T) {
	// Test explicit rate.Inf for comparison
	limiter := rate.NewLimiter(rate.Inf, 100)

	allowed := 0
	for i := 0; i < 10000; i++ {
		if limiter.Allow() {
			allowed++
		}
	}

	if allowed != 10000 {
		t.Errorf("rate.Inf should allow all requests, got %d/10000", allowed)
	}
}
