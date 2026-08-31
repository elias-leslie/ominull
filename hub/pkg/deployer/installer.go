package deployer

import (
	"fmt"
	"strings"

	"ominull/hub/pkg/bootstrap"
	"ominull/hub/pkg/storage"
)

// renderInstaller builds the enrolment script for one push deploy.
//
// It resolves the same two credentials the hub's own bootstrap route does, and
// for the same reasons: the agent is left holding the tenant key, not the admin
// key that authorised the deploy, and its certificate is obtained with a token
// that works once.
func (d *Deployer) renderInstaller(targetOS string, req DeployRequest) (string, error) {
	if d.store == nil {
		return "", fmt.Errorf("no store is configured, so no enrolment credential can be resolved")
	}

	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = "default"
	}
	tenant, err := d.store.GetTenant(tenantID)
	if err != nil {
		return "", fmt.Errorf("resolving tenant %q: %w", tenantID, err)
	}
	if tenant == nil || strings.TrimSpace(tenant.APIKey) == "" {
		return "", fmt.Errorf("tenant %q has no API key to enrol against", tenantID)
	}

	token, err := d.store.CreateEnrollmentToken(req.EndpointID, storage.EnrollmentTokenTTL)
	if err != nil {
		return "", fmt.Errorf("minting an enrolment token: %w", err)
	}

	hubURL := strings.TrimSpace(req.HubURL)
	if hubURL == "" {
		hubURL = d.hubURL
	}

	opts := bootstrap.Options{
		HubURL:          hubURL,
		AgentHubURL:     d.agentHubURL,
		TenantAPIKey:    tenant.APIKey,
		EnrollmentToken: token,
		LocationID:      req.LocationID,
		RoleTag:         req.Role,
		EndpointID:      req.EndpointID,
		AgentVersion:    d.agentVersion,
	}

	switch targetOS {
	case "windows":
		return bootstrap.GeneratePowerShell(opts) + "\n", nil
	default:
		return bootstrap.GenerateBash(opts) + "\n", nil
	}
}
