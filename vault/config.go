package vault

import "time"

// KDFParams configures Argon2id hardness values.
type KDFParams struct {
	MemoryMB uint32
	Time     uint32
	Threads  uint8
	KeyLen   uint32
}

// DefaultKDFParams returns defaults reasonable for desktops/laptops.
func DefaultKDFParams() KDFParams {
	return KDFParams{
		MemoryMB: 256,
		Time:     2,
		Threads:  1,
		KeyLen:   32,
	}
}

// SyncConfig controls outbound sync client behavior.
type SyncConfig struct {
	AppID        string // Required UUID for app namespace isolation
	BaseURL      string
	DeviceID     string
	AuthToken    string
	RefreshToken string    // for automatic token refresh
	TokenExpires time.Time // when current token expires
	Timeout      time.Duration
	Retry        RetryConfig // retry settings (zero uses defaults)

	// AllowUnprefixedEntities enables backward compatibility mode for legacy data.
	// When true, entities without the AppID prefix will be processed during pull.
	// Use this for apps that have existing data from before namespace isolation was added.
	AllowUnprefixedEntities bool

	// OnTokenRefresh is called when tokens are refreshed.
	// Clients should persist the new tokens.
	OnTokenRefresh func(token, refreshToken string, expires time.Time)
}

// GetRetryConfig returns Retry config or defaults if not set.
func (c SyncConfig) GetRetryConfig() RetryConfig {
	if c.Retry.MaxAttempts == 0 {
		return DefaultRetryConfig()
	}
	return c.Retry
}
