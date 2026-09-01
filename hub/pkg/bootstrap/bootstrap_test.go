package bootstrap

import (
	"strings"
	"testing"
)

func TestGeneratedBashSelectsPinnedOrSystemTrust(t *testing.T) {
	for _, test := range []struct {
		name       string
		useSystem  bool
		marker     string
		pinSetting string
	}{
		{name: "self-issued", marker: "USE_SYSTEM_CA=0", pinSetting: "pin_hub_ca=$PIN_HUB_CA"},
		{name: "public", useSystem: true, marker: "USE_SYSTEM_CA=1", pinSetting: "pin_hub_ca=$PIN_HUB_CA"},
	} {
		t.Run(test.name, func(t *testing.T) {
			script := GenerateBash(Options{HubURL: "https://hub.example.invalid", UseSystemCA: test.useSystem})
			if !strings.Contains(script, test.marker) || !strings.Contains(script, test.pinSetting) {
				t.Fatalf("trust mode was not rendered: marker=%q pin=%q", test.marker, test.pinSetting)
			}
			if strings.Contains(script, "__USE_SYSTEM_CA__") || strings.Contains(script, "__HUB_URL__") {
				t.Fatal("generated script contains an unresolved template marker")
			}
		})
	}
}

func TestGeneratedPowerShellSelectsPinnedOrSystemTrust(t *testing.T) {
	script := GeneratePowerShell(Options{HubURL: "https://hub.example.invalid", UseSystemCA: true})
	for _, marker := range []string{"$UseSystemCA = $true", "curl.exe @CurlTLS", "pin_hub_ca=$PinHubCA", "ca_source=$caSource"} {
		if !strings.Contains(script, marker) {
			t.Fatalf("generated PowerShell script lacks %q", marker)
		}
	}
	if strings.Contains(script, "__USE_SYSTEM_CA__") {
		t.Fatal("generated PowerShell script contains an unresolved template marker")
	}
}
