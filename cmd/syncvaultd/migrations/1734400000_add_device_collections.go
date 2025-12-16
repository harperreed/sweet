// ABOUTME: Adds sync_devices and revoked_devices collections for v0.3.0 device validation.
// ABOUTME: Safe to run on existing databases - skips if collections already exist.

package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		// sync_devices collection (skip if exists)
		if _, err := app.FindCollectionByNameOrId("sync_devices"); err != nil {
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
		}

		// revoked_devices collection (skip if exists)
		if _, err := app.FindCollectionByNameOrId("revoked_devices"); err != nil {
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
		}

		return nil
	}, func(app core.App) error {
		// Down migration - only remove if we created them
		for _, name := range []string{"revoked_devices", "sync_devices"} {
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
