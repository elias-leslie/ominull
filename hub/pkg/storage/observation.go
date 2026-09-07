package storage

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// FlowObservation describes how a record was measured. Missing metadata is
// unknown provenance, never proof that bytes were counted on the wire.
type FlowObservation struct {
	Incomplete bool       `json:"incomplete,omitempty"`
	Timing     string     `json:"timing,omitempty"`
	Source     string     `json:"source,omitempty"`
	ByteBasis  string     `json:"byte_basis,omitempty"`
	Count      uint64     `json:"count,omitempty"`
	FirstAt    *time.Time `json:"first_at,omitempty"`
	LastAt     *time.Time `json:"last_at,omitempty"`
	Lost       uint64     `json:"lost,omitempty"`
}

func (o FlowObservation) Value() (driver.Value, error) {
	b, err := json.Marshal(o)
	return string(b), err
}
func (o *FlowObservation) Scan(value any) error { return scanObservationJSON(value, o) }

type CollectorHealth struct {
	BuffersLost   uint64 `json:"buffers_lost,omitempty"`
	ScopeOmitted  uint64 `json:"scope_omitted,omitempty"`
	SchemaOmitted uint64 `json:"schema_omitted,omitempty"`
	Unmeasured    uint64 `json:"unmeasured,omitempty"`
	Deferred      uint64 `json:"deferred,omitempty"`
	Name          string `json:"name"`
	State         string `json:"state"`
	Error         int    `json:"error,omitempty"`
	Dropped       uint64 `json:"dropped"`
	Queued        uint64 `json:"queued"`
}
type CollectorHealthList []CollectorHealth

func (h CollectorHealthList) Value() (driver.Value, error) {
	b, err := json.Marshal(h)
	return string(b), err
}
func (h *CollectorHealthList) Scan(value any) error { return scanObservationJSON(value, h) }
func scanObservationJSON(value any, target any) error {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		return json.Unmarshal([]byte(v), target)
	case []byte:
		return json.Unmarshal(v, target)
	default:
		return fmt.Errorf("invalid observation JSON storage type %T", value)
	}
}
