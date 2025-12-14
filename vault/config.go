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
	BaseURL   string
	DeviceID  string
	AuthToken string
	Timeout   time.Duration
}
