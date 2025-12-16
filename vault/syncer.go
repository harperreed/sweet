// ABOUTME: Syncer provides high-level sync operations combining Store and Client.
// ABOUTME: It handles entity prefixing for app namespace isolation.
package vault

import (
	"context"
	"encoding/json"
)

// Syncer coordinates local store and remote sync client.
type Syncer struct {
	store  *Store
	client *Client
	keys   Keys
	userID string
}

// NewSyncer creates a syncer that manages encryption and entity prefixing.
func NewSyncer(store *Store, client *Client, keys Keys, userID string) *Syncer {
	return &Syncer{
		store:  store,
		client: client,
		keys:   keys,
		userID: userID,
	}
}

// QueueChange creates, encrypts, and queues a change for push.
// Entity is automatically prefixed with AppID for namespace isolation.
// Returns the Change with prefixed entity name.
func (s *Syncer) QueueChange(ctx context.Context, entity, entityID string, op Op, payload any) (Change, error) {
	// Prefix entity with AppID before creating change
	prefixedEntity := s.client.prefixedEntity(entity)

	change, err := NewChange(prefixedEntity, entityID, op, payload)
	if err != nil {
		return Change{}, err
	}

	// Serialize change to plaintext
	plain, err := json.Marshal(change)
	if err != nil {
		return Change{}, err
	}

	// Generate AAD with prefixed entity (already in change.Entity)
	aad := change.AAD(s.userID, s.client.cfg.DeviceID)

	// Encrypt with AAD binding
	env, err := Encrypt(s.keys.EncKey, plain, aad)
	if err != nil {
		return Change{}, err
	}

	// Enqueue encrypted change
	if err := s.store.EnqueueEncryptedChange(ctx, change, s.userID, s.client.cfg.DeviceID, env); err != nil {
		return Change{}, err
	}

	return change, nil
}
