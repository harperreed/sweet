// ABOUTME: PocketBase collections migration for syncvaultd.
// ABOUTME: Creates collections for users, devices, tokens, challenges, changes, and snapshots.

package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

//nolint:funlen // Migration init functions are necessarily long
func init() {
	m.Register(func(app core.App) error {
		// sync_users collection
		syncUsers := core.NewBaseCollection("sync_users")
		syncUsers.Fields.Add(
			&core.TextField{
				Name:     "user_id",
				Required: true,
			},
		)
		syncUsers.AddIndex("idx_sync_users_user_id", true, "user_id", "")
		if err := app.Save(syncUsers); err != nil {
			return err
		}

		// sync_devices collection
		syncDevices := core.NewBaseCollection("sync_devices")
		syncDevices.Fields.Add(
			&core.TextField{
				Name:     "device_id",
				Required: true,
			},
			&core.TextField{
				Name:     "user_id",
				Required: true,
			},
			&core.TextField{
				Name:     "ssh_pubkey",
				Required: true,
			},
			&core.TextField{
				Name:     "ssh_pubkey_fp",
				Required: true,
			},
			&core.TextField{
				Name: "name",
			},
			&core.NumberField{
				Name: "last_used_at",
			},
		)
		syncDevices.AddIndex("idx_sync_devices_device_id", true, "device_id", "")
		syncDevices.AddIndex("idx_sync_devices_ssh_pubkey_fp", true, "ssh_pubkey_fp", "")
		syncDevices.AddIndex("idx_sync_devices_user_id", false, "user_id", "")
		if err := app.Save(syncDevices); err != nil {
			return err
		}

		// sync_challenges collection
		syncChallenges := core.NewBaseCollection("sync_challenges")
		syncChallenges.Fields.Add(
			&core.TextField{
				Name:     "challenge_id",
				Required: true,
			},
			&core.TextField{
				Name:     "user_id",
				Required: true,
			},
			&core.TextField{
				Name:     "challenge",
				Required: true,
			},
			&core.NumberField{
				Name:     "expires_at",
				Required: true,
			},
		)
		syncChallenges.AddIndex("idx_sync_challenges_challenge_id", true, "challenge_id", "")
		syncChallenges.AddIndex("idx_sync_challenges_user_exp", false, "user_id, expires_at", "")
		if err := app.Save(syncChallenges); err != nil {
			return err
		}

		// sync_tokens collection
		syncTokens := core.NewBaseCollection("sync_tokens")
		syncTokens.Fields.Add(
			&core.TextField{
				Name:     "token_hash",
				Required: true,
			},
			&core.TextField{
				Name:     "user_id",
				Required: true,
			},
			&core.TextField{
				Name: "device_id",
			},
			&core.NumberField{
				Name:     "expires_at",
				Required: true,
			},
		)
		syncTokens.AddIndex("idx_sync_tokens_token_hash", true, "token_hash", "")
		syncTokens.AddIndex("idx_sync_tokens_device", false, "device_id", "")
		syncTokens.AddIndex("idx_sync_tokens_user_exp", false, "user_id, expires_at", "")
		if err := app.Save(syncTokens); err != nil {
			return err
		}

		// sync_changes collection
		syncChanges := core.NewBaseCollection("sync_changes")
		syncChanges.Fields.Add(
			&core.NumberField{
				Name:     "seq",
				Required: true,
			},
			&core.TextField{
				Name:     "user_id",
				Required: true,
			},
			&core.TextField{
				Name:     "change_id",
				Required: true,
			},
			&core.TextField{
				Name:     "device_id",
				Required: true,
			},
			&core.TextField{
				Name:     "entity",
				Required: true,
			},
			&core.NumberField{
				Name:     "ts",
				Required: true,
			},
			&core.TextField{
				Name:     "nonce_b64",
				Required: true,
			},
			&core.TextField{
				Name:     "ct_b64",
				Required: true,
			},
		)
		syncChanges.AddIndex("idx_sync_changes_user_change", true, "user_id, change_id", "")
		syncChanges.AddIndex("idx_sync_changes_user_seq", false, "user_id, seq", "")
		if err := app.Save(syncChanges); err != nil {
			return err
		}

		// sync_snapshots collection
		syncSnapshots := core.NewBaseCollection("sync_snapshots")
		syncSnapshots.Fields.Add(
			&core.TextField{
				Name:     "snapshot_id",
				Required: true,
			},
			&core.TextField{
				Name:     "user_id",
				Required: true,
			},
			&core.TextField{
				Name:     "entity",
				Required: true,
			},
			&core.NumberField{
				Name:     "min_seq",
				Required: true,
			},
			&core.TextField{
				Name:     "nonce_b64",
				Required: true,
			},
			&core.TextField{
				Name:     "ct_b64",
				Required: true,
			},
		)
		syncSnapshots.AddIndex("idx_sync_snapshots_snapshot_id", true, "snapshot_id", "")
		syncSnapshots.AddIndex("idx_sync_snapshots_user_entity", false, "user_id, entity", "")
		if err := app.Save(syncSnapshots); err != nil {
			return err
		}

		return nil
	}, func(app core.App) error {
		// Down migration - remove collections
		collections := []string{
			"sync_snapshots",
			"sync_changes",
			"sync_tokens",
			"sync_challenges",
			"sync_devices",
			"sync_users",
		}
		for _, name := range collections {
			col, err := app.FindCollectionByNameOrId(name)
			if err != nil {
				continue
			}
			if err := app.Delete(col); err != nil {
				return err
			}
		}
		return nil
	})
}
