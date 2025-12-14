// ABOUTME: Per-user rate limiting using token bucket algorithm.
// ABOUTME: Protects server from runaway clients and abuse.

package main

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitConfig holds rate limiter settings.
type RateLimitConfig struct {
	Interval time.Duration // Time between allowed requests
	Burst    int           // Max burst size
}

// DefaultRateLimitConfig returns ~100 req/min with burst of 10.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Interval: 600 * time.Millisecond,
		Burst:    10,
	}
}

// rateLimiterStore manages per-user rate limiters.
type rateLimiterStore struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
	config   RateLimitConfig
}

func newRateLimiterStore(config RateLimitConfig) *rateLimiterStore {
	return &rateLimiterStore{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
	}
}

func (s *rateLimiterStore) get(userID string) *rate.Limiter {
	s.mu.RLock()
	limiter, ok := s.limiters[userID]
	s.mu.RUnlock()
	if ok {
		return limiter
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check after acquiring write lock
	if limiter, ok := s.limiters[userID]; ok {
		return limiter
	}
	limiter = rate.NewLimiter(rate.Every(s.config.Interval), s.config.Burst)
	s.limiters[userID] = limiter
	return limiter
}

func (s *rateLimiterStore) setConfig(interval time.Duration, burst int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = RateLimitConfig{Interval: interval, Burst: burst}
	// Clear existing limiters so they pick up new config
	s.limiters = make(map[string]*rate.Limiter)
}
