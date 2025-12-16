// ABOUTME: Per-user and per-IP rate limiting using token bucket algorithm.
// ABOUTME: Protects server from runaway clients and abuse.

package main

import (
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitConfig holds rate limiter settings.
// Setting Interval <= 0 disables rate limiting (unlimited requests).
type RateLimitConfig struct {
	Interval time.Duration // Time between allowed requests (0 or negative = disabled)
	Burst    int           // Max burst size
}

// DefaultRateLimitConfig returns ~100 req/min with burst of 10.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Interval: 600 * time.Millisecond,
		Burst:    10,
	}
}

// AuthRateLimitConfig returns stricter limits for auth endpoints (~10 req/min).
func AuthRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Interval: 6 * time.Second,
		Burst:    5,
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
	limiter = s.newLimiter()
	s.limiters[userID] = limiter
	return limiter
}

// newLimiter creates a rate limiter with the current config.
// If Interval <= 0, rate limiting is disabled (unlimited rate).
func (s *rateLimiterStore) newLimiter() *rate.Limiter {
	if s.config.Interval <= 0 {
		// Explicitly disable rate limiting with infinite rate
		return rate.NewLimiter(rate.Inf, s.config.Burst)
	}
	return rate.NewLimiter(rate.Every(s.config.Interval), s.config.Burst)
}

// setConfig updates the rate limit configuration.
// If interval <= 0, rate limiting is effectively disabled (unlimited rate).
// Existing limiters are cleared to pick up the new config.
func (s *rateLimiterStore) setConfig(interval time.Duration, burst int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = RateLimitConfig{Interval: interval, Burst: burst}
	// Clear existing limiters so they pick up new config
	s.limiters = make(map[string]*rate.Limiter)
}

// getClientIP extracts client IP from request.
// Only trusts X-Forwarded-For/X-Real-IP headers when TRUSTED_PROXY=1 env var is set.
// Otherwise uses RemoteAddr to prevent header spoofing attacks.
func getClientIP(r *http.Request) string {
	// Only trust proxy headers if explicitly configured
	if os.Getenv("TRUSTED_PROXY") == "1" {
		// Check X-Forwarded-For header (first IP in chain is the client)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP in the list (before first comma)
			for i, c := range xff {
				if c == ',' {
					return xff[:i]
				}
			}
			return xff
		}

		// Check X-Real-IP header
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}

	// Use RemoteAddr (direct connection IP)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
