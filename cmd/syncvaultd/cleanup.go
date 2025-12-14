// ABOUTME: Background cleanup routines for expired tokens and challenges.
// ABOUTME: Prevents unbounded growth of auth-related tables.

package main

import (
	"context"
	"log"
	"time"
)

// CleanupStats tracks how many records were purged.
type CleanupStats struct {
	tokens     int64
	challenges int64
}

// cleanupExpired deletes expired tokens and challenges, returning counts.
func (s *Server) cleanupExpired(ctx context.Context) CleanupStats {
	now := time.Now().Unix()
	var stats CleanupStats

	res, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE expires_at < ?`, now)
	if err != nil {
		log.Printf("cleanup tokens error: %v", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		stats.tokens = n
	}

	res, err = s.db.ExecContext(ctx, `DELETE FROM challenges WHERE expires_at < ?`, now)
	if err != nil {
		log.Printf("cleanup challenges error: %v", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		stats.challenges = n
	}

	return stats
}

// startCleanupRoutine runs cleanup every hour in background.
func (s *Server) startCleanupRoutine(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := s.cleanupExpired(ctx)
				if stats.tokens > 0 || stats.challenges > 0 {
					log.Printf("cleanup: purged %d tokens, %d challenges", stats.tokens, stats.challenges)
				}
			}
		}
	}()
}
