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
				Name: "name",
			},
			&core.NumberField{
				Name: "last_used_at",
			},
		)
		syncDevices.AddIndex("idx_sync_devices_device_id", true, "device_id", "")
		syncDevices.AddIndex("idx_sync_devices_user_id", false, "user_id", "")
		if err := app.Save(syncDevices); err != nil {
			return err
		}

		// revoked_devices collection
		revokedDevices := core.NewBaseCollection("revoked_devices")
		revokedDevices.Fields.Add(
			&core.TextField{
				Name:     "device_id",
				Required: true,
			},
			&core.TextField{
				Name:     "user_id",
				Required: true,
			},
			&core.NumberField{
				Name:     "revoked_at",
				Required: true,
			},
		)
		revokedDevices.AddIndex("idx_revoked_devices_user_device", true, "user_id, device_id", "")
		if err := app.Save(revokedDevices); err != nil {
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
				Max:      100, // Nonces are small fixed size
			},
			&core.TextField{
				Name:     "ct_b64",
				Required: true,
				Max:      1000000, // 1MB to support large encrypted payloads
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
				Max:      100, // Nonces are small fixed size
			},
			&core.TextField{
				Name:     "ct_b64",
				Required: true,
				Max:      10000000, // 10MB for snapshots (can aggregate many changes)
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
			"revoked_devices",
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
