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

const cleanupBatchSize = 1000

// cleanupExpired deletes expired tokens and challenges, returning counts.
//
//nolint:nestif,unparam // Cleanup needs nested loops for batch deletion; ctx reserved for future use.
func (s *Server) cleanupExpired(_ context.Context) CleanupStats {
	now := time.Now().Unix()
	var stats CleanupStats

	// Clean up expired tokens (loop until all deleted)
	tokensCol, err := s.app.FindCollectionByNameOrId("sync_tokens")
	if err != nil {
		log.Printf("cleanup: find tokens collection error: %v", err)
	} else {
		for {
			expiredTokens, err := s.app.FindRecordsByFilter(tokensCol, "expires_at < {:now}", "", cleanupBatchSize, 0,
				map[string]any{"now": now})
			if err != nil {
				log.Printf("cleanup: query expired tokens error: %v", err)
				break
			}
			if len(expiredTokens) == 0 {
				break
			}
			for _, t := range expiredTokens {
				if err := s.app.Delete(t); err != nil {
					log.Printf("cleanup: delete token error: %v", err)
				} else {
					stats.tokens++
				}
			}
		}
	}

	// Clean up expired challenges (loop until all deleted)
	challengesCol, err := s.app.FindCollectionByNameOrId("sync_challenges")
	if err != nil {
		log.Printf("cleanup: find challenges collection error: %v", err)
	} else {
		for {
			expiredChallenges, err := s.app.FindRecordsByFilter(challengesCol, "expires_at < {:now}", "", cleanupBatchSize, 0,
				map[string]any{"now": now})
			if err != nil {
				log.Printf("cleanup: query expired challenges error: %v", err)
				break
			}
			if len(expiredChallenges) == 0 {
				break
			}
			for _, c := range expiredChallenges {
				if err := s.app.Delete(c); err != nil {
					log.Printf("cleanup: delete challenge error: %v", err)
				} else {
					stats.challenges++
				}
			}
		}
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
