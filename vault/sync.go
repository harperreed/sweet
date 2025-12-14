package vault

import (
	"context"
	"encoding/json"
	"strconv"
)

// ApplyFn applies a decrypted change to application state.
type ApplyFn func(ctx context.Context, c Change) error

// Sync flushes local outbox then pulls remote updates.
func Sync(ctx context.Context, store *Store, client *Client, keys Keys, apply ApplyFn) error {
	userID := keys.UserID()

	items, err := store.DequeueBatch(ctx, 200)
	if err != nil {
		return err
	}
	if len(items) > 0 {
		pushItems := make([]PushItem, 0, len(items))
		for _, it := range items {
			pushItems = append(pushItems, PushItem(it))
		}
		resp, err := client.Push(ctx, userID, pushItems)
		if err != nil {
			return err
		}
		if err := store.AckOutbox(ctx, resp.Ack); err != nil {
			return err
		}
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
