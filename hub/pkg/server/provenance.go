package server

import (
	"fmt"
	"strings"

	"ominull/hub/pkg/storage"
)

// Native package identities are part of the wire contract. Keep them in one
// place so package builders, telemetry, and the fleet gate cannot silently
// disagree about what "installed" means.
const (
	linuxAgentPackageID   = "ominull-agent"
	windowsAgentPackageID = "OminullAgent"
)

type nativePackage struct {
	InstallType string
	Identifier  string
}

func nativePackageForCapability(capability string) (nativePackage, bool) {
	switch strings.ToLower(strings.TrimSpace(capability)) {
	case "deb":
		return nativePackage{InstallType: "deb", Identifier: linuxAgentPackageID}, true
	case "msi":
		return nativePackage{InstallType: "msi", Identifier: windowsAgentPackageID}, true
	default:
		return nativePackage{}, false
	}
}

// provenanceIssue returns an operator-readable reason when an endpoint cannot
// be counted as a native-package installation at the requested binary version.
// Legacy/manual and missing reports stay visible even when the binary version
// is current; release status refuses to count them as converged.
func provenanceIssue(ep storage.Endpoint, targetVersion string) string {
	if compareVersions(ep.DriverVersion, targetVersion) < 0 {
		return "binary version is outdated"
	}
	expected, ok := nativePackageForCapability(ep.UpdateCapability)
	if !ok {
		return "agent reports no native package capability"
	}
	if strings.TrimSpace(ep.ProvenanceStatus) != "native" {
		status := strings.TrimSpace(ep.ProvenanceStatus)
		if status == "" {
			status = "unknown"
		}
		return "provenance status is " + status
	}
	if ep.InstallType != expected.InstallType {
		return fmt.Sprintf("install type %q does not match %q", ep.InstallType, expected.InstallType)
	}
	if ep.PackageIdentifier != expected.Identifier {
		return fmt.Sprintf("package identifier %q does not match %q", ep.PackageIdentifier, expected.Identifier)
	}
	if compareVersions(ep.RegisteredPackageVersion, ep.DriverVersion) != 0 {
		return fmt.Sprintf("registered package version %q does not match binary %q", ep.RegisteredPackageVersion, ep.DriverVersion)
	}
	return ""
}
