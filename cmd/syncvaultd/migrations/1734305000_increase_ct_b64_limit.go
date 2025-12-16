// ABOUTME: Migration to increase ct_b64 field limit for large encrypted payloads.
// ABOUTME: Fixes 500 error when syncing payloads larger than ~5KB.

package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		// Update sync_changes collection
		// Skip if collection doesn't exist (fresh installs get correct limits from base migration)
		syncChanges, err := app.FindCollectionByNameOrId("sync_changes")
		if err != nil {
			return nil // Collection doesn't exist yet, skip
		}

		// Find and update the ct_b64 field
		for i, field := range syncChanges.Fields {
			if textField, ok := field.(*core.TextField); ok {
				if textField.Name == "ct_b64" {
					textField.Max = 1000000 // 1MB for encrypted payloads
					syncChanges.Fields[i] = textField
				}
				if textField.Name == "nonce_b64" {
					textField.Max = 100 // Nonces are small fixed size
					syncChanges.Fields[i] = textField
				}
			}
		}
		if err := app.Save(syncChanges); err != nil {
			return err
		}

		// Update sync_snapshots collection
		syncSnapshots, err := app.FindCollectionByNameOrId("sync_snapshots")
		if err != nil {
			return err
		}

		for i, field := range syncSnapshots.Fields {
			if textField, ok := field.(*core.TextField); ok {
				if textField.Name == "ct_b64" {
					textField.Max = 10000000 // 10MB for snapshots
					syncSnapshots.Fields[i] = textField
				}
				if textField.Name == "nonce_b64" {
					textField.Max = 100
					syncSnapshots.Fields[i] = textField
				}
			}
		}
		if err := app.Save(syncSnapshots); err != nil {
			return err
		}

		return nil
	}, func(app core.App) error {
		// Down migration - revert to original limits
		syncChanges, err := app.FindCollectionByNameOrId("sync_changes")
		if err != nil {
			return err
		}

		for i, field := range syncChanges.Fields {
			if textField, ok := field.(*core.TextField); ok {
				if textField.Name == "ct_b64" || textField.Name == "nonce_b64" {
					textField.Max = 0 // Default
					syncChanges.Fields[i] = textField
				}
			}
		}
		if err := app.Save(syncChanges); err != nil {
			return err
		}

		syncSnapshots, err := app.FindCollectionByNameOrId("sync_snapshots")
		if err != nil {
			return err
		}

		for i, field := range syncSnapshots.Fields {
			if textField, ok := field.(*core.TextField); ok {
				if textField.Name == "ct_b64" || textField.Name == "nonce_b64" {
					textField.Max = 0
					syncSnapshots.Fields[i] = textField
				}
			}
		}
		return app.Save(syncSnapshots)
	})
}
