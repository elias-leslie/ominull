package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TopologyConversation is an observed relation, not a claim that DNS identifies
// a machine or that two independent reporters measured distinct connections.
type TopologyConversation struct {
	Source       string    `json:"source"`
	Target       string    `json:"target"`
	EndpointID   string    `json:"endpoint_id"`
	Process      string    `json:"process"`
	Domain       string    `json:"domain"`
	DomainSource string    `json:"domain_source"`
	Protocol     int       `json:"protocol"`
	Port         int       `json:"port"`
	Action       string    `json:"action"`
	FlowCount    int64     `json:"flow_count"`
	TotalBytes   int64     `json:"total_bytes"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

type TopologyWorkspace struct {
	TopologyData
	Conversations     []TopologyConversation `json:"conversations"`
	EvidenceTruncated bool                   `json:"evidence_truncated"`
	From              time.Time              `json:"from"`
	To                time.Time              `json:"to"`
}

func (s *Store) GetTopologyWorkspace(window time.Duration) (TopologyWorkspace, error) {
	// Freeze one interval for graph and evidence queries.
	to := time.Now().UTC()
	conversations := []TopologyConversation{}
	graph, err := s.topologyGraphBetween(to.Add(-window), to, window, &conversations)
	if err != nil {
		return TopologyWorkspace{}, err
	}
	out := TopologyWorkspace{TopologyData: graph, Conversations: []TopologyConversation{}, From: to.Add(-window), To: to}
	ids := map[string]string{}
	for i := range out.Nodes {
		n := &out.Nodes[i]
		id := n.AssetID
		if id == "" && n.EndpointID != "" {
			id = "endpoint:" + n.EndpointID
		}
		if id == "" {
			id = "address:" + n.IP
		}
		ids[n.ID] = id
		n.ID = id
	}
	for i := range out.Edges {
		e := &out.Edges[i]
		e.Source = ids[e.Source]
		e.Target = ids[e.Target]
		key, _ := json.Marshal([]string{e.Source, e.Target})
		e.ID = string(key)
	}
	if len(conversations) > 20000 {
		out.EvidenceTruncated = true
		conversations = conversations[:20000]
	}
	for _, conversation := range conversations {
		conversation.Source, conversation.Target = ids[conversation.Source], ids[conversation.Target]
		out.Conversations = append(out.Conversations, conversation)
	}
	return out, nil
}

type TopologyView struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Revision  int64           `json:"revision"`
	State     json.RawMessage `json:"state"`
	UpdatedAt time.Time       `json:"updated_at"`
}

var ErrTopologyViewConflict = errors.New("saved view changed or no longer exists; reload before saving")

func (s *Store) ListTopologyViews(owner string) ([]TopologyView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT id,name,revision,state,updated_at FROM topology_views WHERE owner=? ORDER BY name,id`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TopologyView{}
	for rows.Next() {
		var v TopologyView
		var raw string
		var at interface{}
		if err := rows.Scan(&v.ID, &v.Name, &v.Revision, &raw, &at); err != nil {
			return nil, err
		}
		v.State = json.RawMessage(raw)
		v.UpdatedAt = scanTime(at)
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) SaveTopologyView(owner string, v TopologyView) (TopologyView, error) {
	if owner == "" || len(v.ID) > 100 || v.ID == "" || strings.TrimSpace(v.Name) == "" || len(v.Name) > 100 || len(v.State) > 1024*1024 || !validTopologyViewState(v.State) || v.Revision < 0 {
		return v, fmt.Errorf("invalid saved view")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v.Name = strings.TrimSpace(v.Name)
	v.UpdatedAt = time.Now().UTC()
	if v.Revision == 0 {
		res, err := s.db.Exec(`INSERT INTO topology_views(owner,id,name,revision,state,updated_at) VALUES(?,?,?,1,?,?) ON CONFLICT(owner,id) DO NOTHING`, owner, v.ID, v.Name, string(v.State), v.UpdatedAt)
		if err != nil {
			return v, err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return v, ErrTopologyViewConflict
		}
	} else {
		res, err := s.db.Exec(`UPDATE topology_views SET name=?,revision=revision+1,state=?,updated_at=? WHERE owner=? AND id=? AND revision=?`, v.Name, string(v.State), v.UpdatedAt, owner, v.ID, v.Revision)
		if err != nil {
			return v, err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return v, ErrTopologyViewConflict
		}
	}
	v.Revision++
	return v, nil
}
func (s *Store) DeleteTopologyView(owner, id string, revision int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM topology_views WHERE owner=? AND id=? AND revision=?`, owner, id, revision)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrTopologyViewConflict
	}
	return nil
}

// Validate types before persisting state that the graph renderer consumes.
func validTopologyViewState(raw json.RawMessage) bool {
	if len(strings.TrimSpace(string(raw))) == 0 || strings.TrimSpace(string(raw))[0] != '{' {
		return false
	}
	var state struct {
		Scope *struct {
			Kind    string `json:"kind"`
			ID      string `json:"id"`
			Process string `json:"process"`
			Peer    string `json:"peer"`
		} `json:"scope"`
		ScopeLimit int               `json:"scopeLimit"`
		ScopeLabel string            `json:"scopeLabel"`
		Trail      []json.RawMessage `json:"trail"`
		Coverage   string            `json:"coverage"`
		Protocol   string            `json:"protocol"`
		Verdict    string            `json:"verdict"`
		Mode       string            `json:"mode"`
		List       bool              `json:"list"`
		ActiveOnly bool              `json:"activeOnly"`
		Group      string            `json:"group"`
		Window     string            `json:"window"`
		Query      string            `json:"query"`
		Positions  map[string]struct {
			X float64 `json:"x"`
			Y float64 `json:"y"`
		} `json:"positions"`
		Expanded         map[string]int    `json:"expanded"`
		Regions          bool              `json:"regions"`
		RegionOverrides  map[string]string `json:"regionOverrides"`
		CollapsedRegions map[string]bool   `json:"collapsedRegions"`
		Pins             []string          `json:"pins"`
		Viewport         *struct {
			Zoom float64 `json:"zoom"`
			Pan  struct {
				X float64 `json:"x"`
				Y float64 `json:"y"`
			} `json:"pan"`
		} `json:"viewport"`
	}
	if json.Unmarshal(raw, &state) != nil || len(state.Query) > 512 || len(state.Positions) > 20000 || len(state.Pins) > 20000 {
		return false
	}
	if state.ScopeLimit < 0 || state.ScopeLimit > 1500 || len(state.ScopeLabel) > 4096 || len(state.Trail) > 12 {
		return false
	}
	if state.Scope != nil {
		switch state.Scope.Kind {
		case "overview", "region", "group", "host", "process":
		default:
			return false
		}
		if (state.Scope.Kind != "overview" && state.Scope.ID == "") || len(state.Scope.ID) > 4096 || len(state.Scope.Peer) > 4096 || len(state.Scope.Process) > 4096 {
			return false
		}
	}
	for _, entry := range state.Trail {
		var fields map[string]json.RawMessage
		if json.Unmarshal(entry, &fields) != nil || fields == nil {
			return false
		}
		if _, nested := fields["trail"]; nested {
			return false
		}
		if !validTopologyViewState(entry) {
			return false
		}
	}
	for _, region := range state.RegionOverrides {
		switch region {
		case "", "internal", "virtual", "external", "discovery", "unknown":
		default:
			return false
		}
	}
	switch state.Group {
	case "", "network", "role", "coverage":
	default:
		return false
	}
	switch state.Window {
	case "", "1h", "6h", "24h", "7d":
	default:
		return false
	}
	if state.Viewport != nil && (state.Viewport.Zoom < 0.12 || state.Viewport.Zoom > 2.8) {
		return false
	}
	for _, count := range state.Expanded {
		if count < 0 || count > 100000 {
			return false
		}
	}
	return true
}
