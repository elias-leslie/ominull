package responseauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"ominull/hub/pkg/response"
)

// Client defines the interface used by the hub to interact with the Response Authority.
type Client interface {
	GetTenantPublicKey(ctx context.Context, tenantID string) (ed25519.PublicKey, string, error)
	EnrollTOTP(ctx context.Context, tenantID, operatorID string) (string, error)
	UnlockSession(ctx context.Context, tenantID, operatorID, browserSessionID, browserPubKeyHex, totpCode string) (*ResponseSession, error)
	LockSession(ctx context.Context, sessionID string) error
	SignGrant(ctx context.Context, req *SignGrantRequest) (*response.EndpointGrant, error)
	GenerateRecoveryToken(ctx context.Context, tenantID, operatorID string) (string, error)
	Status(ctx context.Context, tenantID string) (*ResponseAuthorityStatus, error)
}

// UDSClient connects to the response authority over a Unix domain socket.
type UDSClient struct {
	httpClient *http.Server
	client     *http.Client
	socketPath string
}

// NewUDSClient creates a new client communicating over a Unix domain socket.
func NewUDSClient(socketPath string) *UDSClient {
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 5 * time.Second,
	}
	return &UDSClient{
		client:     httpClient,
		socketPath: socketPath,
	}
}

func (c *UDSClient) GetTenantPublicKey(ctx context.Context, tenantID string) (ed25519.PublicKey, string, error) {
	reqURL := fmt.Sprintf("http://unix/v1/auth/tenant-key?tenant_id=%s", url.QueryEscape(tenantID))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("server returned %d: %s", resp.StatusCode, string(b))
	}

	var res struct {
		PublicKey string `json:"public_key"`
		KeyID     string `json:"key_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, "", err
	}
	pubBytes, err := hex.DecodeString(res.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return ed25519.PublicKey(pubBytes), res.KeyID, nil
}

func (c *UDSClient) EnrollTOTP(ctx context.Context, tenantID, operatorID string) (string, error) {
	payload, _ := json.Marshal(map[string]string{
		"tenant_id":   tenantID,
		"operator_id": operatorID,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/auth/totp/enroll", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server returned %d: %s", resp.StatusCode, string(b))
	}
	var res struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	return res.Secret, nil
}

func (c *UDSClient) UnlockSession(ctx context.Context, tenantID, operatorID, browserSessionID, browserPubKeyHex, totpCode string) (*ResponseSession, error) {
	payload, _ := json.Marshal(map[string]string{
		"tenant_id":          tenantID,
		"operator_id":        operatorID,
		"browser_session_id": browserSessionID,
		"browser_public_key": browserPubKeyHex,
		"totp_code":          totpCode,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/auth/session/unlock", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(b))
	}
	var sess ResponseSession
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

func (c *UDSClient) LockSession(ctx context.Context, sessionID string) error {
	payload, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/auth/session/lock", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *UDSClient) SignGrant(ctx context.Context, req *SignGrantRequest) (*response.EndpointGrant, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/auth/grant/sign", bytes.NewReader(payload))
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("authority rejected sign grant (%d): %s", resp.StatusCode, string(b))
	}

	var res SignGrantResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return res.Grant, nil
}

func (c *UDSClient) GenerateRecoveryToken(ctx context.Context, tenantID, operatorID string) (string, error) {
	payload, _ := json.Marshal(map[string]string{
		"tenant_id":   tenantID,
		"operator_id": operatorID,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/auth/recovery/generate", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server returned %d: %s", resp.StatusCode, string(b))
	}
	var res struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	return res.Token, nil
}

func (c *UDSClient) Status(ctx context.Context, tenantID string) (*ResponseAuthorityStatus, error) {
	reqURL := fmt.Sprintf("http://unix/v1/auth/status?tenant_id=%s", url.QueryEscape(tenantID))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(b))
	}
	var status ResponseAuthorityStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	return &status, nil
}

// InProcessClient directly wraps *Authority without network overhead.
type InProcessClient struct {
	auth *Authority
}

// NewInProcessClient creates a direct in-memory client.
func NewInProcessClient(auth *Authority) *InProcessClient {
	return &InProcessClient{auth: auth}
}

func (c *InProcessClient) GetTenantPublicKey(_ context.Context, tenantID string) (ed25519.PublicKey, string, error) {
	return c.auth.GetOrCreateTenantKey(tenantID)
}

func (c *InProcessClient) EnrollTOTP(_ context.Context, tenantID, operatorID string) (string, error) {
	return c.auth.EnrollTOTP(tenantID, operatorID)
}

func (c *InProcessClient) UnlockSession(_ context.Context, tenantID, operatorID, browserSessionID, browserPubKeyHex, totpCode string) (*ResponseSession, error) {
	return c.auth.UnlockSessionWithTOTP(tenantID, operatorID, browserSessionID, browserPubKeyHex, totpCode)
}

func (c *InProcessClient) LockSession(_ context.Context, sessionID string) error {
	return c.auth.LockSession(sessionID)
}

func (c *InProcessClient) SignGrant(_ context.Context, req *SignGrantRequest) (*response.EndpointGrant, error) {
	return c.auth.SignGrant(req)
}

func (c *InProcessClient) GenerateRecoveryToken(_ context.Context, tenantID, operatorID string) (string, error) {
	return c.auth.GenerateRecoveryToken(tenantID, operatorID)
}

func (c *InProcessClient) Status(_ context.Context, tenantID string) (*ResponseAuthorityStatus, error) {
	st := c.auth.Status(tenantID)
	return &st, nil
}

var _ Client = (*UDSClient)(nil)
var _ Client = (*InProcessClient)(nil)
