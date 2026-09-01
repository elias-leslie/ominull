package storage

import (
	"path/filepath"
	"testing"
)

func TestDeviceCredentialIsUniqueRotatableAndRevocable(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "device.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	first, _, err := s.IssueDeviceCredential("ep-one")
	if err == nil {
		t.Fatal("credential was issued for a missing endpoint")
	}
	if err := s.UpsertEndpoint(Endpoint{ID: "ep-one", TenantID: "default", Hostname: "host", OS: "Linux", IP: "10.0.0.1", DriverVersion: "1.0.0", Status: "online"}); err != nil {
		t.Fatal(err)
	}
	first, _, err = s.IssueDeviceCredential("ep-one")
	if err != nil {
		t.Fatal(err)
	}
	auth, ok, err := s.VerifyDeviceCredential(first)
	if err != nil || !ok || auth.EndpointID != "ep-one" || auth.TenantID != "default" {
		t.Fatalf("first credential did not authenticate: %+v %v %v", auth, ok, err)
	}

	second, _, err := s.IssueDeviceCredential("ep-one")
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("credential rotation reused the credential")
	}
	if _, ok, err := s.VerifyDeviceCredential(first); err != nil || ok {
		t.Fatalf("rotated credential remained valid: ok=%v err=%v", ok, err)
	}
	if _, ok, err := s.VerifyDeviceCredential(second); err != nil || !ok {
		t.Fatalf("new credential did not authenticate: ok=%v err=%v", ok, err)
	}
	if err := s.RevokeDeviceCredentials("ep-one"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.VerifyDeviceCredential(second); err != nil || ok {
		t.Fatalf("revoked credential remained valid: ok=%v err=%v", ok, err)
	}

	items, err := s.ListDeviceCredentials()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.EndpointID != "ep-one" || item.ID == first || item.ID == second {
			t.Fatalf("unsafe or malformed credential listing: %+v", item)
		}
	}
}

func TestDeleteDisposableEndpointIsPrefixScoped(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "disposable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.UpsertEndpoint(Endpoint{ID: "diagnostic-one", TenantID: "default", Hostname: "probe", OS: "Linux", IP: "127.0.0.1", DriverVersion: "diagnostic", Status: "offline"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.IssueDeviceCredential("diagnostic-one"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDisposableEndpoint("normal-one"); err == nil {
		t.Fatal("non-diagnostic endpoint was accepted for deletion")
	}
	if err := s.DeleteDisposableEndpoint("diagnostic-one"); err != nil {
		t.Fatal(err)
	}
	if endpoint, err := s.GetEndpoint("diagnostic-one"); err != nil || endpoint != nil {
		t.Fatalf("disposable endpoint remained: endpoint=%+v err=%v", endpoint, err)
	}
	credentials, err := s.ListDeviceCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 0 {
		t.Fatalf("disposable device credential remained: %d", len(credentials))
	}
}
