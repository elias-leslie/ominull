package responseauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"ominull/hub/pkg/response"
)

func writeAuthorityJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func approvalErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrApprovalNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrApprovalRateLimit):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrNoApprovers):
		return http.StatusServiceUnavailable
	default:
		return http.StatusForbidden
	}
}

func (s *Server) registerApprovalRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/approvals/request", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAuthorityJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var in ApprovalRequestInput
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&in); err != nil {
			writeAuthorityJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		v, err := s.auth.RequestApproval(&in)
		if err != nil {
			writeAuthorityJSON(w, approvalErrorStatus(err), map[string]string{"error": err.Error()})
			return
		}
		writeAuthorityJSON(w, http.StatusOK, v)
	})
	mux.HandleFunc("/v1/approvals/get", func(w http.ResponseWriter, r *http.Request) {
		v, err := s.auth.GetApproval(r.URL.Query().Get("id"), r.URL.Query().Get("tenant_id"))
		if err != nil {
			writeAuthorityJSON(w, approvalErrorStatus(err), map[string]string{"error": err.Error()})
			return
		}
		writeAuthorityJSON(w, http.StatusOK, v)
	})
	mux.HandleFunc("/v1/approvals/pending", func(w http.ResponseWriter, r *http.Request) {
		writeAuthorityJSON(w, http.StatusOK, map[string]interface{}{"approvals": s.auth.PendingApprovals()})
	})
	mux.HandleFunc("/v1/approvals/answer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAuthorityJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var ans ApprovalAnswer
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&ans); err != nil {
			writeAuthorityJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		v, err := s.auth.AnswerApproval(&ans)
		if err != nil {
			writeAuthorityJSON(w, approvalErrorStatus(err), map[string]interface{}{"error": err.Error(), "approval": v})
			return
		}
		writeAuthorityJSON(w, http.StatusOK, v)
	})
	mux.HandleFunc("/v1/approvals/consume", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAuthorityJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req ApprovalConsumeRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
			writeAuthorityJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		grants, err := s.auth.ConsumeApproval(&req)
		if err != nil {
			writeAuthorityJSON(w, approvalErrorStatus(err), map[string]string{"error": err.Error()})
			return
		}
		writeAuthorityJSON(w, http.StatusOK, map[string]interface{}{"grants": grants})
	})
}

// ApprovalClient is the owner-approval half of the authority API.
type ApprovalClient interface {
	RequestApproval(ctx context.Context, in *ApprovalRequestInput) (*ApprovalView, error)
	GetApproval(ctx context.Context, id, tenantID string) (*ApprovalView, error)
	PendingApprovals(ctx context.Context) ([]ApprovalView, error)
	AnswerApproval(ctx context.Context, ans *ApprovalAnswer) (*ApprovalView, error)
	ConsumeApproval(ctx context.Context, req *ApprovalConsumeRequest) ([]*response.EndpointGrant, error)
}

// ApprovalError carries the authority's status for a refused approval call.
type ApprovalError struct {
	Status  int
	Message string
}

func (e *ApprovalError) Error() string { return e.Message }

func (c *UDSClient) approvalCall(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("authority returned %d", resp.StatusCode)
		}
		return &ApprovalError{Status: resp.StatusCode, Message: e.Error}
	}
	return json.Unmarshal(raw, out)
}

func (c *UDSClient) RequestApproval(ctx context.Context, in *ApprovalRequestInput) (*ApprovalView, error) {
	var v ApprovalView
	if err := c.approvalCall(ctx, http.MethodPost, "/v1/approvals/request", in, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *UDSClient) GetApproval(ctx context.Context, id, tenantID string) (*ApprovalView, error) {
	var v ApprovalView
	q := url.Values{"id": {id}, "tenant_id": {tenantID}}
	if err := c.approvalCall(ctx, http.MethodGet, "/v1/approvals/get?"+q.Encode(), nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *UDSClient) PendingApprovals(ctx context.Context) ([]ApprovalView, error) {
	var out struct {
		Approvals []ApprovalView `json:"approvals"`
	}
	if err := c.approvalCall(ctx, http.MethodGet, "/v1/approvals/pending", nil, &out); err != nil {
		return nil, err
	}
	return out.Approvals, nil
}

func (c *UDSClient) AnswerApproval(ctx context.Context, ans *ApprovalAnswer) (*ApprovalView, error) {
	var v ApprovalView
	if err := c.approvalCall(ctx, http.MethodPost, "/v1/approvals/answer", ans, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *UDSClient) ConsumeApproval(ctx context.Context, req *ApprovalConsumeRequest) ([]*response.EndpointGrant, error) {
	var out struct {
		Grants []*response.EndpointGrant `json:"grants"`
	}
	if err := c.approvalCall(ctx, http.MethodPost, "/v1/approvals/consume", req, &out); err != nil {
		return nil, err
	}
	return out.Grants, nil
}

func asApprovalError(err error) error {
	if err == nil {
		return nil
	}
	return &ApprovalError{Status: approvalErrorStatus(err), Message: err.Error()}
}

func (c *InProcessClient) RequestApproval(_ context.Context, in *ApprovalRequestInput) (*ApprovalView, error) {
	v, err := c.auth.RequestApproval(in)
	return v, asApprovalError(err)
}

func (c *InProcessClient) GetApproval(_ context.Context, id, tenantID string) (*ApprovalView, error) {
	v, err := c.auth.GetApproval(id, tenantID)
	return v, asApprovalError(err)
}

func (c *InProcessClient) PendingApprovals(_ context.Context) ([]ApprovalView, error) {
	return c.auth.PendingApprovals(), nil
}

func (c *InProcessClient) AnswerApproval(_ context.Context, ans *ApprovalAnswer) (*ApprovalView, error) {
	v, err := c.auth.AnswerApproval(ans)
	return v, asApprovalError(err)
}

func (c *InProcessClient) ConsumeApproval(_ context.Context, req *ApprovalConsumeRequest) ([]*response.EndpointGrant, error) {
	g, err := c.auth.ConsumeApproval(req)
	return g, asApprovalError(err)
}

var _ ApprovalClient = (*UDSClient)(nil)
var _ ApprovalClient = (*InProcessClient)(nil)
