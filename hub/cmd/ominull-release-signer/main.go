// ominull-release-signer is the OMINULL_SIGNING_COMMAND for OmniNull releases; see pkg/releasesigner.
package main

import (
	"os"

	"ominull/hub/pkg/releasesigner"
)

func main() { os.Exit(releasesigner.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
