// ABOUTME: Syncer provides high-level sync operations combining Store and Client.
// ABOUTME: It handles entity prefixing for app namespace isolation.
package vault

import (
	"context"
	"encoding/json"
)

// Syncer coordinates local store and remote sync client.
type Syncer struct {
	store   *Store
	client  *Client
	keys    Keys
	userID  string
	applyFn ApplyFn
}

// NewSyncer creates a syncer that manages encryption and entity prefixing.
// The apply function is called during sync to apply remote changes to local state.
// Pass nil if you only need to queue changes without pulling.
func NewSyncer(store *Store, client *Client, keys Keys, userID string, apply ApplyFn) *Syncer {
	return &Syncer{
		store:   store,
		client:  client,
		keys:    keys,
		userID:  userID,
		applyFn: apply,
	}
}

// CanSync returns true if the client is configured for remote sync.
func (s *Syncer) CanSync() bool {
	return s.client != nil &&
		s.client.cfg.BaseURL != "" &&
		s.client.cfg.AuthToken != "" &&
		s.userID != ""
}

// Sync pushes local changes and pulls remote changes.
// Uses the ApplyFn provided at construction time.
func (s *Syncer) Sync(ctx context.Context, events ...*SyncEvents) error {
	var ev *SyncEvents
	if len(events) > 0 {
		ev = events[0]
	}
	return Sync(ctx, s.store, s.client, s.keys, s.userID, s.applyFn, ev)
}

// QueueAndSync queues a change and immediately syncs if configured.
// This is the recommended method for most use cases - it ensures changes
// are pushed to the server right away rather than waiting for manual sync.
func (s *Syncer) QueueAndSync(ctx context.Context, entity, entityID string, op Op, payload any, events ...*SyncEvents) (Change, error) {
	change, err := s.QueueChange(ctx, entity, entityID, op, payload)
	if err != nil {
		return Change{}, err
	}

	if s.CanSync() {
		if err := s.Sync(ctx, events...); err != nil {
			// Return the change even on sync error - it's queued locally
			return change, err
		}
	}

	return change, nil
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
