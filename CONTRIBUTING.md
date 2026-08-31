# Contributing

Keep changes scoped to the retained hub, Linux agent, Windows agent, native
packages, and recovery tooling. Do not add unverified enforcement claims or a
second control channel.

Before a commit:

```bash
scripts/version.sh check
gofmt -w $(find hub -name '*.go' -type f)
(cd hub && go test -race ./... && go vet ./...)
node --check hub/pkg/server/web/app.js
bash -n scripts/*.sh
```

Build and exercise package ownership with `scripts/build-packages.sh` and
`scripts/test-package-lifecycle.sh`. Use `scripts/release.sh` for a release;
it builds, signs, installs the hub first, and checks endpoint convergence.

Never commit credentials, certificates, package signatures from another key,
private deployment values, databases, or generated binaries. Use the operations
vault and the ignored deployment hook for live credentials.

Preserve unrelated working-tree changes. Inspect staged diffs for scope,
secrets, durable-data deletion, and package payloads before pushing.
