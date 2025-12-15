// ABOUTME: Migration to create refresh_tokens collection for PocketBase auth.
// ABOUTME: Stores single-use refresh tokens with expiration for persistent sessions.
package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		collection := core.NewBaseCollection("refresh_tokens")
		collection.Fields.Add(
			&core.TextField{
				Name:     "user",
				Required: true,
			},
			&core.TextField{
				Name:     "token_hash",
				Required: true,
			},
			&core.DateField{
				Name:     "expires",
				Required: true,
			},
		)
		collection.AddIndex("idx_refresh_tokens_hash", true, "token_hash", "")
		collection.AddIndex("idx_refresh_tokens_user", false, "user", "")
		return app.Save(collection)
	}, func(app core.App) error {
		collection, err := app.FindCollectionByNameOrId("refresh_tokens")
		if err != nil {
			return nil //nolint:nilerr // Collection doesn't exist; rollback is a no-op.
		}
		return app.Delete(collection)
	})
}
