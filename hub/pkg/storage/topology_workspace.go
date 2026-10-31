package storage

import (
	"encoding/json"
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
