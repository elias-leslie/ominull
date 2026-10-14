package server

import (
	"encoding/json"
	"sort"
	"time"
)

// Data inventory in the Nightshift feed (nightshift.findings/v3).
//
// v3 is v2 plus data_inventory: one block per scanned endpoint with its scan
// summary, host facts, stores and flagged items, as metadata (paths, sizes,
// times, counts, rule names). Nightshift runs on the hub's own host and keeps
// the paths local; it generalises them before any model outside the host sees
// one. Blocks are cut to fit the document cap, and say so.

const (
	nightshiftSchemaV3 = "nightshift.findings/v3"
	// v4 is v3 plus each anomaly record's detection tier (nightshift_records.go).
	nightshiftSchemaV4    = "nightshift.findings/v4"
	feedDocumentBytesV3   = 960 << 10
	feedDataStoresPerHost = 400
	feedDataItemsPerHost  = 400
	feedDataMinStoresKept = 25
	// Nightshift's v3 caps (src/nightshift/ingest.py): blocks per document and
	// host facts per block. Kept here so a valid hub never sends what the
	// reader must cut.
	feedDataMaxBlocks    = 64
	feedDataMaxHostBytes = 32 << 10
)

var feedStoreKeys = []string{"path", "root", "shallow", "partial", "files", "dirs", "bytes", "newest_mtime", "oldest_mtime",
	"world_readable", "group_readable", "world_writable", "setid", "items", "owner_uid", "owners", "ext", "hints", "errors", "truncated"}
var feedItemKeys = []string{"path", "store", "kind", "rules", "mode", "uid", "size", "mtime"}
var feedRunKeys = []string{"mode", "cycle_complete", "budget_hit", "files", "dirs", "content_files", "stores", "items",
	"items_dropped", "stores_dropped", "errors", "skipped_canary", "policy_version", "rules_version", "sandboxed"}

func pickKeys(raw json.RawMessage, keys []string) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	out := make(map[string]json.RawMessage, len(keys))
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

type feedDataBlock struct {
	EndpointID      string                       `json:"endpoint_id"`
	DeviceID        string                       `json:"device_id"`
	Scan            map[string]any               `json:"scan"`
	Host            json.RawMessage              `json:"host,omitempty"`
	Stores          []map[string]json.RawMessage `json:"stores"`
	Items           []map[string]json.RawMessage `json:"items"`
	StoresTruncated bool                         `json:"stores_truncated"`
	ItemsTruncated  bool                         `json:"items_truncated"`
}

// dataInventoryBlocks builds the v3 blocks within budget bytes of JSON.
func (s *Server) dataInventoryBlocks(now time.Time, budget int) ([]feedDataBlock, bool, error) {
	ids, err := s.store.DataInventoryEndpoints()
	if err != nil {
		return nil, false, err
	}
	salt, err := s.deviceSalt()
	if err != nil {
		return nil, false, err
	}
	blocks := []feedDataBlock{}
	for _, id := range ids {
		snap, ok, err := s.store.DataSnapshotFor(id, feedDataStoresPerHost, feedDataItemsPerHost)
		if err != nil {
			return nil, false, err
		}
		if !ok || snap.LastRun == nil {
			continue
		}
		scan := map[string]any{"last_run_at": snap.LastRun.FinishedAt, "last_complete_at": snap.LastCompleteAt,
			"received_at": snap.LastRun.ReceivedAt.UnixMilli(), "cycle_id": snap.LastRun.CycleID}
		for k, v := range pickKeys(snap.LastRun.Summary, feedRunKeys) {
			scan[k] = v
		}
		host := snap.Host
		if len(host) > feedDataMaxHostBytes {
			host = nil // over the reader's cap: unknown host facts, the block still goes
		}
		b := feedDataBlock{EndpointID: id, DeviceID: deviceID(salt, id), Scan: scan, Host: host,
			Stores: []map[string]json.RawMessage{}, Items: []map[string]json.RawMessage{},
			StoresTruncated: snap.StoresTruncated, ItemsTruncated: snap.ItemsTruncated}
		for _, st := range snap.Stores {
			if m := pickKeys(st.Doc, feedStoreKeys); m != nil {
				b.Stores = append(b.Stores, m)
			}
		}
		for _, it := range snap.Items {
			if m := pickKeys(it.Doc, feedItemKeys); m != nil {
				b.Items = append(b.Items, m)
			}
		}
		blocks = append(blocks, b)
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].EndpointID < blocks[j].EndpointID })
	truncated := false
	if len(blocks) > feedDataMaxBlocks {
		blocks, truncated = blocks[:feedDataMaxBlocks], true
	}
	// Fit the budget: halve the largest block's store list (items are what a
	// reader acts on, so they go last) until the whole fits.
	size := func() int { raw, _ := json.Marshal(blocks); return len(raw) }
	for size() > budget {
		cut := false
		big := -1
		for i := range blocks {
			if len(blocks[i].Stores) > feedDataMinStoresKept && (big < 0 || len(blocks[i].Stores) > len(blocks[big].Stores)) {
				big = i
			}
		}
		if big >= 0 {
			blocks[big].Stores = blocks[big].Stores[:len(blocks[big].Stores)/2]
			blocks[big].StoresTruncated = true
			cut = true
		} else {
			for i := range blocks {
				if len(blocks[i].Items) > 10 && (big < 0 || len(blocks[i].Items) > len(blocks[big].Items)) {
					big = i
				}
			}
			if big >= 0 {
				blocks[big].Items = blocks[big].Items[:len(blocks[big].Items)/2]
				blocks[big].ItemsTruncated = true
				cut = true
			}
		}
		if !cut {
			blocks = blocks[:len(blocks)-1]
			truncated = true
			if len(blocks) == 0 {
				break
			}
		}
	}
	_ = now
	return blocks, truncated, nil
}
