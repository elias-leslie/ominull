package responseauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

// ApprovalRowsClient carries the owner's Approvals rows between the hub's
// Nightshift relay routes and the authority, which decides everything.
type ApprovalRowsClient interface {
	ApprovalRows(ctx context.Context, tenantID string) (*ApprovalRowsView, error)
	AskApprovalRows(ctx context.Context, in *ApprovalRowsInput) (*ApprovalRowsAsk, error)
	SetApprovalRows(ctx context.Context, in *ApprovalRowsInput) (*ApprovalRowsResult, error)
}

func (s *Server) registerApprovalRowsRoutes(mux *http.ServeMux) {
	decode := func(w http.ResponseWriter, r *http.Request) (*ApprovalRowsInput, bool) {
		if r.Method != http.MethodPost {
			writeAuthorityJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return nil, false
		}
		var in ApprovalRowsInput
		dec := json.NewDecoder(io.LimitReader(r.Body, 16*1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			writeAuthorityJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rows: " + err.Error()})
			return nil, false
		}
		return &in, true
	}
	mux.HandleFunc("/v1/approvals/rows", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeAuthorityJSON(w, http.StatusOK, s.auth.ApprovalRowsView(r.URL.Query().Get("tenant_id")))
			return
		}
		in, ok := decode(w, r)
		if !ok {
			return
		}
		res, err := s.auth.SetApprovalRows(in)
		if err != nil {
			writeAuthorityJSON(w, approvalErrorStatus(err), map[string]interface{}{"error": err.Error(), "result": res})
			return
		}
		writeAuthorityJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("/v1/approvals/rows/ask", func(w http.ResponseWriter, r *http.Request) {
		in, ok := decode(w, r)
		if !ok {
			return
		}
		res, err := s.auth.AskApprovalRows(in)
		if err != nil {
			writeAuthorityJSON(w, approvalErrorStatus(err), map[string]string{"error": err.Error()})
			return
		}
		writeAuthorityJSON(w, http.StatusOK, res)
	})
}

func (c *UDSClient) ApprovalRows(ctx context.Context, tenantID string) (*ApprovalRowsView, error) {
	var v ApprovalRowsView
	if err := c.approvalCall(ctx, http.MethodGet, "/v1/approvals/rows?"+url.Values{"tenant_id": {tenantID}}.Encode(), nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *UDSClient) AskApprovalRows(ctx context.Context, in *ApprovalRowsInput) (*ApprovalRowsAsk, error) {
	var v ApprovalRowsAsk
	if err := c.approvalCall(ctx, http.MethodPost, "/v1/approvals/rows/ask", in, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *UDSClient) SetApprovalRows(ctx context.Context, in *ApprovalRowsInput) (*ApprovalRowsResult, error) {
	var v ApprovalRowsResult
	if err := c.approvalCall(ctx, http.MethodPost, "/v1/approvals/rows", in, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *InProcessClient) ApprovalRows(_ context.Context, tenantID string) (*ApprovalRowsView, error) {
	v := c.auth.ApprovalRowsView(tenantID)
	return &v, nil
}

func (c *InProcessClient) AskApprovalRows(_ context.Context, in *ApprovalRowsInput) (*ApprovalRowsAsk, error) {
	v, err := c.auth.AskApprovalRows(in)
	return v, asApprovalError(err)
}

func (c *InProcessClient) SetApprovalRows(_ context.Context, in *ApprovalRowsInput) (*ApprovalRowsResult, error) {
	v, err := c.auth.SetApprovalRows(in)
	return v, asApprovalError(err)
}

var _ ApprovalRowsClient = (*UDSClient)(nil)
var _ ApprovalRowsClient = (*InProcessClient)(nil)
