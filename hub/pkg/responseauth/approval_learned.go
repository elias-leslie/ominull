package responseauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Learning (Nightshift's approvals model): when the owner has approved the
// same job shape learnedAfter times with no denial, and it is not core, the
// authority approves that shape without asking from then on. Any denial of
// the shape removes it at once, as does Nightshift naming it in a rows save's
// forget list (the owner's undo on "Approved for you").
const (
	learnedAfter     = 3
	learnedMaxShapes = 500
)

// LearnedShape is one job shape the owner has approved.
type LearnedShape struct {
	Shape     string    `json:"shape"`
	Kind      string    `json:"kind"`
	Action    string    `json:"action"`
	Targets   []string  `json:"targets"`
	Approvals int       `json:"approvals"`
	Auto      bool      `json:"auto"`
	Approver  string    `json:"approver,omitempty"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
}

type learnedBook struct {
	mu    sync.Mutex
	path  string
	items map[string]map[string]*LearnedShape // tenant -> shape -> record
	err   error
}

func newLearnedBook(stateDir string) *learnedBook {
	b := &learnedBook{items: map[string]map[string]*LearnedShape{}}
	if stateDir == "" {
		return b
	}
	b.path = filepath.Join(stateDir, "learned_approvals.json")
	raw, err := os.ReadFile(b.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		b.err = fmt.Errorf("learned approvals unreadable: %w", err)
	default:
		if json.Unmarshal(raw, &b.items) != nil || b.items == nil {
			// Unreadable: nothing is approved by learning until the owner
			// approves shapes again.
			b.err = fmt.Errorf("learned approvals file %s is corrupt", b.path)
			b.items = map[string]map[string]*LearnedShape{}
		}
	}
	return b
}

// volatileKeys change from one run of the same job to the next.
var volatileKeys = map[string]bool{
	"nonce": true, "run_id": true, "idempotency_key": true, "requested_at": true,
	"deadline": true, "expires_at": true, "started": true, "created": true, "reason": true,
}

func stripVolatile(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if !volatileKeys[k] {
				out[k] = stripVolatile(e)
			}
		}
		return out
	case []any:
		for i := range x {
			x[i] = stripVolatile(x[i])
		}
		return x
	}
	return v
}

// approvalShape is a job's shape: its kind, targets, what the owner is shown
// beside the payload, and the payload without its per-run fields.
func approvalShape(in *ApprovalRequestInput, targets []string) string {
	var p any
	if json.Unmarshal(in.Payload, &p) != nil {
		return ""
	}
	raw, err := json.Marshal(map[string]any{
		"kind": string(in.Kind), "targets": targets, "session_seconds": in.SessionSeconds,
		"ask_first": in.AskFirst, "agent": in.AgentLabel, "payload": stripVolatile(p),
	})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

func (b *learnedBook) match(tenant, shape string) (LearnedShape, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r := b.items[tenantOrDefault(tenant)][shape]; r != nil && r.Auto && shape != "" {
		return *r, true
	}
	return LearnedShape{}, false
}

// approve counts one owner approval of the shape; it says whether the shape
// just became automatic.
func (b *learnedBook) approve(tenant string, rec LearnedShape, now time.Time) (bool, error) {
	if rec.Shape == "" {
		return false, nil
	}
	tenant = tenantOrDefault(tenant)
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.items[tenant]
	if m == nil {
		m = map[string]*LearnedShape{}
		b.items[tenant] = m
	}
	cur := m[rec.Shape]
	if cur == nil {
		cur = &rec
		cur.First = now.UTC().Truncate(time.Second)
		m[rec.Shape] = cur
	}
	cur.Approvals++
	cur.Approver, cur.Last, cur.Action = rec.Approver, now.UTC().Truncate(time.Second), rec.Action
	became := !cur.Auto && cur.Approvals >= learnedAfter
	cur.Auto = cur.Auto || became
	if len(m) > learnedMaxShapes {
		var oldest string
		for s, r := range m {
			if !r.Auto && s != rec.Shape && (oldest == "" || r.Last.Before(m[oldest].Last)) {
				oldest = s
			}
		}
		delete(m, oldest)
	}
	return became, b.saveLocked()
}

// forget removes shapes (a denial, or the owner's undo); it says which were
// automatic.
func (b *learnedBook) forget(tenant string, shapes ...string) ([]string, error) {
	tenant = tenantOrDefault(tenant)
	b.mu.Lock()
	defer b.mu.Unlock()
	var wasAuto []string
	changed := false
	for _, s := range shapes {
		if r := b.items[tenant][s]; r != nil {
			if r.Auto {
				wasAuto = append(wasAuto, s)
			}
			delete(b.items[tenant], s)
			changed = true
		}
	}
	if !changed {
		return nil, nil
	}
	return wasAuto, b.saveLocked()
}

func (b *learnedBook) saveLocked() error {
	if b.path == "" {
		return nil
	}
	raw, err := json.Marshal(b.items)
	if err != nil {
		return err
	}
	if err := writeDurable(b.path, raw); err != nil {
		return err
	}
	b.err = nil
	return nil
}

// list is the tenant's learned shapes, automatic first, newest first.
func (b *learnedBook) list(tenant string) []LearnedShape {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []LearnedShape
	for _, r := range b.items[tenantOrDefault(tenant)] {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Auto != out[j].Auto {
			return out[i].Auto
		}
		return out[i].Last.After(out[j].Last)
	})
	return out
}
