package vault

import (
	"context"
	"encoding/json"
	"strconv"
)

// ApplyFn applies a decrypted change to application state.
type ApplyFn func(ctx context.Context, c Change) error

// Sync flushes local outbox then pulls remote updates.
// userID is the server-side user identifier (PocketBase record ID).
// keys is used only for encryption/decryption, not for user identification.
func Sync(ctx context.Context, store *Store, client *Client, keys Keys, userID string, apply ApplyFn) error {
	if err := pushOutbox(ctx, store, client, userID); err != nil {
		return err
	}

	sinceStr, err := store.GetState(ctx, "last_pulled_seq", "0")
	if err != nil {
		return err
	}
	since, _ := strconv.ParseInt(sinceStr, 10, 64)

	pull, err := client.Pull(ctx, userID, since)
	if err != nil {
		return err
	}

	maxSeq := since
	for _, it := range pull.Items {
		aad := []byte("v1|" + userID + "|" + it.DeviceID + "|" + it.ChangeID + "|" + it.Entity)
		plain, err := Decrypt(keys.EncKey, it.Env, aad)
		if err != nil {
			return err
		}
		var c Change
		if err := json.Unmarshal(plain, &c); err != nil {
			return err
		}
		if err := apply(ctx, c); err != nil {
			return err
		}
		if it.Seq > maxSeq {
			maxSeq = it.Seq
		}
	}

	if maxSeq != since {
		if err := store.SetState(ctx, "last_pulled_seq", strconv.FormatInt(maxSeq, 10)); err != nil {
			return err
		}
	}
	return nil
}

// pushOutbox flushes pending changes from the local outbox to the server.
func pushOutbox(ctx context.Context, store *Store, client *Client, userID string) error {
	items, err := store.DequeueBatch(ctx, 200)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
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
		return err
	}
	return store.AckOutbox(ctx, resp.Ack)
}
