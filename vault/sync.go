package vault

import (
	"context"
	"encoding/json"
	"strconv"
)

// ApplyFn applies a decrypted change to application state.
type ApplyFn func(ctx context.Context, c Change) error

// SyncEvents provides hooks for observability during sync operations.
type SyncEvents struct {
	OnStart    func()                      // Called when sync begins
	OnPush     func(pushed, remaining int) // Called after each push batch
	OnPull     func(pulled int)            // Called after pull completes
	OnComplete func(pushed, pulled int)    // Called when sync finishes
}

// Sync flushes local outbox then pulls remote updates.
// userID is the server-side user identifier (PocketBase record ID).
// keys is used only for encryption/decryption, not for user identification.
// Optionally accepts a *SyncEvents for observability hooks.
func Sync(ctx context.Context, store *Store, client *Client, keys Keys, userID string, apply ApplyFn, events ...*SyncEvents) error {
	var ev *SyncEvents
	if len(events) > 0 {
		ev = events[0]
	}
	if ev != nil && ev.OnStart != nil {
		ev.OnStart()
	}

	pushed, err := pushOutboxWithEvents(ctx, store, client, userID, ev)
	if err != nil {
		return err
	}

	sinceStr, err := store.GetState(ctx, "last_pulled_seq", "0")
	if err != nil {
		return err
	}
	since, _ := strconv.ParseInt(sinceStr, 10, 64)

	pulled, maxSeq, err := pullAndApply(ctx, client, keys, userID, since, apply)
	if err != nil {
		return err
	}

	if ev != nil && ev.OnPull != nil {
		ev.OnPull(pulled)
	}
	if maxSeq != since {
		if err := store.SetState(ctx, "last_pulled_seq", strconv.FormatInt(maxSeq, 10)); err != nil {
			return err
		}
	}
	if ev != nil && ev.OnComplete != nil {
		ev.OnComplete(pushed, pulled)
	}
	return nil
}

func pullAndApply(ctx context.Context, client *Client, keys Keys, userID string, since int64, apply ApplyFn) (int, int64, error) {
	pull, err := client.Pull(ctx, userID, since)
	if err != nil {
		return 0, since, err
	}
	maxSeq := since
	pulled := 0
	for _, it := range pull.Items {
		// Filter: only process items from our app namespace
		if !client.hasAppPrefix(it.Entity) {
			// Update maxSeq but don't count as pulled
			if it.Seq > maxSeq {
				maxSeq = it.Seq
			}
			continue
		}

		aad := []byte("v1|" + userID + "|" + it.DeviceID + "|" + it.ChangeID + "|" + it.Entity)
		plain, err := Decrypt(keys.EncKey, it.Env, aad)
		if err != nil {
			return pulled, maxSeq, &DecryptError{
				ChangeID: it.ChangeID,
				Entity:   it.Entity,
				UserID:   userID,
				DeviceID: it.DeviceID,
				Cause:    err,
			}
		}
		var c Change
		if err := json.Unmarshal(plain, &c); err != nil {
			return pulled, maxSeq, err
		}
		// Strip prefix before passing to apply callback
		c.Entity = client.stripPrefix(c.Entity)
		if err := apply(ctx, c); err != nil {
			return pulled, maxSeq, err
		}
		pulled++
		if it.Seq > maxSeq {
			maxSeq = it.Seq
		}
	}
	return pulled, maxSeq, nil
}

// pushOutboxWithEvents flushes pending changes and reports progress via events.
func pushOutboxWithEvents(ctx context.Context, store *Store, client *Client, userID string, ev *SyncEvents) (int, error) {
	totalPushed := 0
	for {
		items, err := store.DequeueBatch(ctx, 200)
		if err != nil {
			return totalPushed, err
		}
		if len(items) == 0 {
			return totalPushed, nil
		}

		pushItems := make([]PushItem, 0, len(items))
		for _, it := range items {
			pushItems = append(pushItems, PushItem{
				ChangeID: it.ChangeID,
				Entity:   it.Entity,
				TS:       it.TS,
				Env:      it.Env,
			})
		}

		resp, err := client.Push(ctx, userID, pushItems)
		if err != nil {
			return totalPushed, err
		}
		if err := store.AckOutbox(ctx, resp.Ack); err != nil {
			return totalPushed, err
		}

		pushed := len(resp.Ack)
		totalPushed += pushed

		// Get remaining count for OnPush callback
		remaining, _ := store.PendingCount(ctx)
		if ev != nil && ev.OnPush != nil {
			ev.OnPush(pushed, remaining)
		}
	}
}
