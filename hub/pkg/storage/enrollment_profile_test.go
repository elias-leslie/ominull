package storage

import "testing"

func TestEnrollmentProfilesSeparateInvitationCampaignAndDeploymentRules(t *testing.T) {
	s := windowStore(t)

	_, invitation, err := s.CreateEnrollmentProfile(EnrollmentProfile{Platform: "linux"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemEnrollmentProfile(invitation, "windows"); err == nil {
		t.Fatal("platform-specific invitation accepted the wrong platform")
	}
	if _, err := s.RedeemEnrollmentProfile(invitation, "linux"); err != nil {
		t.Fatalf("invitation was refused: %v", err)
	}
	if _, err := s.RedeemEnrollmentProfile(invitation, "linux"); err == nil {
		t.Fatal("one-use invitation was reusable")
	}

	_, campaign, err := s.CreateEnrollmentProfile(EnrollmentProfile{Kind: "campaign", Platform: "windows", MaxUses: 0}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.RedeemEnrollmentProfile(campaign, "windows"); err != nil {
			t.Fatalf("unlimited campaign redemption %d failed: %v", i+1, err)
		}
	}

	deployment, deploymentCode, err := s.CreateEnrollmentProfile(EnrollmentProfile{Kind: "deployment", Platform: "linux", TenantID: "default"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if deployment.ExpiresAt.Year() != 9999 || deployment.MaxUses != 0 {
		t.Fatalf("deployment profile is not persistent: %+v", deployment)
	}
	if _, err := s.RedeemEnrollmentProfile(deploymentCode, "linux"); err != nil {
		t.Fatalf("persistent deployment code failed: %v", err)
	}
	if err := s.RevokeEnrollmentProfile(deployment.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemEnrollmentProfile(deploymentCode, "linux"); err == nil {
		t.Fatal("revoked deployment code remained usable")
	}
}

func TestEnrollmentProfileListingDoesNotExposeCode(t *testing.T) {
	s := windowStore(t)
	_, code, err := s.CreateEnrollmentProfile(EnrollmentProfile{Kind: "deployment"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := s.ListEnrollmentProfiles()
	if err != nil || len(profiles) != 1 {
		t.Fatalf("list profiles: %v (%d)", err, len(profiles))
	}
	if profiles[0].ID == code || profiles[0].CreatedBy == code {
		t.Fatalf("enrollment code appeared in listed profile: %+v", profiles[0])
	}
}
