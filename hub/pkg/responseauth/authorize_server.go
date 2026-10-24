package responseauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func authorityErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrAutoIsolateRateLimit):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrManifestNeedsRoute):
		return http.StatusForbidden
	case errors.Is(err, ErrNotAuthorized):
		return http.StatusUnprocessableEntity
	default:
		return http.StatusForbidden
	}
}

func (s *Server) registerAuthorizeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAuthorityJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var in AuthorizeInput
		// A package run carries its script sources (packageMaxPayload).
		if err := json.NewDecoder(io.LimitReader(r.Body, packageMaxPayload+64*1024)).Decode(&in); err != nil {
			writeAuthorityJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		au, err := s.auth.Authorize(&in)
		if err != nil {
			writeAuthorityJSON(w, authorityErrorStatus(err), map[string]string{"error": err.Error()})
			return
		}
		writeAuthorityJSON(w, http.StatusOK, au)
	})
}

// AuthorizeClient is the grant-signing half of the authority API.
type AuthorizeClient interface {
	Authorize(ctx context.Context, in *AuthorizeInput) (*Authorization, error)
}

// AuthorityError carries the authority's status for a refused call.
type AuthorityError struct {
	Status  int
	Message string
}

func (e *AuthorityError) Error() string { return e.Message }

// call sends one request to the authority and decodes its answer; a refusal
// comes back as an *AuthorityError carrying the authority's status.
func (c *UDSClient) call(ctx context.Context, method, path string, body, out interface{}) error {
	var rd io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, rd)
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		msg := string(raw)
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return &AuthorityError{Status: resp.StatusCode, Message: msg}
	}
	return json.Unmarshal(raw, out)
}

func (c *UDSClient) Authorize(ctx context.Context, in *AuthorizeInput) (*Authorization, error) {
	var out Authorization
	if err := c.call(ctx, http.MethodPost, "/v1/authorize", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func asAuthorityError(err error) error {
	if err == nil {
		return nil
	}
	return &AuthorityError{Status: authorityErrorStatus(err), Message: err.Error()}
}

func (c *InProcessClient) Authorize(_ context.Context, in *AuthorizeInput) (*Authorization, error) {
	au, err := c.auth.Authorize(in)
	return au, asAuthorityError(err)
}

var _ AuthorizeClient = (*UDSClient)(nil)
var _ AuthorizeClient = (*InProcessClient)(nil)

// ------------------------------------------------------------- agent trust

func (s *Server) registerTrustRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/trust/keys", func(w http.ResponseWriter, r *http.Request) {
		k, err := s.auth.TrustKeys(r.URL.Query().Get("tenant_id"))
		if err != nil {
			writeAuthorityJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeAuthorityJSON(w, http.StatusOK, k)
	})
	mux.HandleFunc("/v1/trust/auto-isolate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAuthorityJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req AutoIsolateRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 8*1024)).Decode(&req); err != nil {
			writeAuthorityJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		g, err := s.auth.SignAutoIsolation(&req)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, ErrAutoIsolateRateLimit) {
				status = http.StatusTooManyRequests
			}
			writeAuthorityJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		writeAuthorityJSON(w, http.StatusOK, g)
	})
	mux.HandleFunc("/v1/trust/manifest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAuthorityJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req ManifestRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 8*1024)).Decode(&req); err != nil {
			writeAuthorityJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		m, err := s.auth.EndpointManifest(&req)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, ErrManifestNeedsRoute) {
				status = http.StatusForbidden
			}
			writeAuthorityJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		writeAuthorityJSON(w, http.StatusOK, m)
	})
}

// TrustClient is the agent-trust half of the authority API.
type TrustClient interface {
	TrustKeys(ctx context.Context, tenantID string) (*response.TrustKeys, error)
	SignAutoIsolation(ctx context.Context, req *AutoIsolateRequest) (*response.EnforcementGrant, error)
	EndpointManifest(ctx context.Context, req *ManifestRequest) (*response.CapabilityManifest, error)
}

func (c *UDSClient) TrustKeys(ctx context.Context, tenantID string) (*response.TrustKeys, error) {
	var k response.TrustKeys
	if err := c.call(ctx, http.MethodGet, "/v1/trust/keys?"+url.Values{"tenant_id": {tenantID}}.Encode(), nil, &k); err != nil {
		return nil, err
	}
	return &k, nil
}

func (c *UDSClient) SignAutoIsolation(ctx context.Context, req *AutoIsolateRequest) (*response.EnforcementGrant, error) {
	var g response.EnforcementGrant
	if err := c.call(ctx, http.MethodPost, "/v1/trust/auto-isolate", req, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func (c *UDSClient) EndpointManifest(ctx context.Context, req *ManifestRequest) (*response.CapabilityManifest, error) {
	var m response.CapabilityManifest
	if err := c.call(ctx, http.MethodPost, "/v1/trust/manifest", req, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (c *InProcessClient) TrustKeys(_ context.Context, tenantID string) (*response.TrustKeys, error) {
	k, err := c.auth.TrustKeys(tenantID)
	return k, asAuthorityError(err)
}

func (c *InProcessClient) SignAutoIsolation(_ context.Context, req *AutoIsolateRequest) (*response.EnforcementGrant, error) {
	g, err := c.auth.SignAutoIsolation(req)
	return g, asAuthorityError(err)
}

func (c *InProcessClient) EndpointManifest(_ context.Context, req *ManifestRequest) (*response.CapabilityManifest, error) {
	m, err := c.auth.EndpointManifest(req)
	return m, asAuthorityError(err)
}

var _ TrustClient = (*UDSClient)(nil)
var _ TrustClient = (*InProcessClient)(nil)
