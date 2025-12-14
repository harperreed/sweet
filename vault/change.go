package vault

import (
	"encoding/json"
	"time"

	"github.com/oklog/ulid/v2"
)

// Op describes supported logical operations.
type Op string

const (
	OpUpsert Op = "upsert"
	OpDelete Op = "delete"
	OpAppend Op = "append"
)

// Change is the plaintext logical event before encryption.
type Change struct {
	ChangeID    string          `json:"change_id"`
	Entity      string          `json:"entity"`
	EntityID    string          `json:"entity_id"`
	Op          Op              `json:"op"`
	TS          time.Time       `json:"ts"`
	Payload     json.RawMessage `json:"payload,omitempty"`
	Deleted     bool            `json:"deleted,omitempty"`
	BaseVersion int64           `json:"base_version,omitempty"`
}

// NewChange builds a change with a ULID and marshalled payload.
func NewChange(entity, entityID string, op Op, payload any) (Change, error) {
	id := ulid.Make().String()
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return Change{}, err
		}
		raw = b
	}
	return Change{
		ChangeID: id,
		Entity:   entity,
		EntityID: entityID,
		Op:       op,
		TS:       time.Now().UTC(),
		Payload:  raw,
	}, nil
}

// NewChangeWithVersion builds a change that tracks the base version.
func NewChangeWithVersion(entity, entityID string, op Op, payload any, baseVersion int64) (Change, error) {
	c, err := NewChange(entity, entityID, op, payload)
	if err != nil {
		return Change{}, err
	}
	c.BaseVersion = baseVersion
	return c, nil
}

// AAD produces deterministic binding bytes for encryption.
func (c Change) AAD(userID, deviceID string) []byte {
	return []byte("v1|" + userID + "|" + deviceID + "|" + c.ChangeID + "|" + c.Entity)
}
