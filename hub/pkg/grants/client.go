package grants

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"

	"ominull/hub/pkg/response"
)

// Client is what the hub calls; a test can stand in a refusing one.
type Client interface {
	GetTenantPublicKey(ctx context.Context, tenantID string) (ed25519.PublicKey, string, error)
	SignGrant(ctx context.Context, req *SignGrantRequest) (*response.EndpointGrant, error)
	Authorize(ctx context.Context, in *AuthorizeInput) (*Authorization, error)
	TrustKeys(ctx context.Context, tenantID string) (*response.TrustKeys, error)
	SignAutoIsolation(ctx context.Context, req *AutoIsolateRequest) (*response.EnforcementGrant, error)
	EndpointManifest(ctx context.Context, req *ManifestRequest) (*response.CapabilityManifest, error)
}

// RefusalError carries the HTTP status of a refused signature.
type RefusalError struct {
	Status  int
	Message string
}

func (e *RefusalError) Error() string { return e.Message }

func refusal(err error) error {
	if err == nil {
		return nil
	}
	status := http.StatusForbidden
	switch {
	case errors.Is(err, ErrAutoIsolateRateLimit):
		status = http.StatusTooManyRequests
	case errors.Is(err, ErrNotAuthorized):
		status = http.StatusUnprocessableEntity
	}
	return &RefusalError{Status: status, Message: err.Error()}
}

type localClient struct{ s *Signer }

// NewClient is the hub's view of a signer.
func NewClient(s *Signer) Client { return localClient{s} }

func (c localClient) GetTenantPublicKey(_ context.Context, tenantID string) (ed25519.PublicKey, string, error) {
	return c.s.GetOrCreateTenantKey(tenantID)
}

func (c localClient) SignGrant(_ context.Context, req *SignGrantRequest) (*response.EndpointGrant, error) {
	g, err := c.s.SignGrant(req)
	return g, refusal(err)
}

func (c localClient) Authorize(_ context.Context, in *AuthorizeInput) (*Authorization, error) {
	au, err := c.s.Authorize(in)
	return au, refusal(err)
}

func (c localClient) TrustKeys(_ context.Context, tenantID string) (*response.TrustKeys, error) {
	k, err := c.s.TrustKeys(tenantID)
	return k, refusal(err)
}

func (c localClient) SignAutoIsolation(_ context.Context, req *AutoIsolateRequest) (*response.EnforcementGrant, error) {
	g, err := c.s.SignAutoIsolation(req)
	return g, refusal(err)
}

func (c localClient) EndpointManifest(_ context.Context, req *ManifestRequest) (*response.CapabilityManifest, error) {
	m, err := c.s.EndpointManifest(req)
	return m, refusal(err)
}
