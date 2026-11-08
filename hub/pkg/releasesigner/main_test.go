package releasesigner

import (
	"os"
	"testing"

	"ominull/hub/pkg/testguard"
)

func TestMain(m *testing.M) {
	cleanup := testguard.Install()
	code := testguard.Finish(m.Run())
	cleanup()
	os.Exit(code)
}
