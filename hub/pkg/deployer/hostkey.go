package deployer

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// hostKeySettingPrefix namespaces the recorded keys in the settings table.
const hostKeySettingPrefix = "ssh_hostkey:"

// keyFingerprint renders a host key the way ssh-keyscan and OpenSSH do, so an
// operator can compare what the hub recorded against what they see on the host
// without converting between formats.
func keyFingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

// hostKeyCallback resolves how this target's identity is checked, and returns a
// second function reporting the fingerprint if one was recorded on first
// contact.
//
// Three cases, in order of how much the operator has told us:
//
//   - An explicit host_key_fingerprint in the request. It must match. This is
//     the only mode that is safe against an attacker who is already on the path
//     the very first time the hub reaches this address.
//   - A key recorded on a previous deploy. It must match, and a change is
//     refused rather than reported and carried on past - a host key that
//     changed under a push deploy is either a rebuild or an interception, and
//     an operator has to say which.
//   - Neither. The key is accepted, recorded, and printed into the job log.
//     Trust on first use is weaker than a pin and stronger than accepting
//     anything on every connection, which is what this replaces.
func (d *Deployer) hostKeyCallback(req DeployRequest) (ssh.HostKeyCallback, func() string, error) {
	pinned := strings.TrimSpace(req.HostKeyFingerprint)
	addr := net.JoinHostPort(req.TargetIP, fmt.Sprint(req.Port))
	settingKey := hostKeySettingPrefix + addr

	var known string
	if d.store != nil {
		known, _ = d.store.GetSetting(settingKey)
		known = strings.TrimSpace(known)
	}
	if pinned == "" {
		pinned = known
	}

	var (
		mu       sync.Mutex
		recorded string
	)

	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := keyFingerprint(key)
		if pinned != "" {
			if fp != pinned {
				return fmt.Errorf(
					"the host key for %s is %s, not the %s this hub expected; refusing to hand credentials to it. "+
						"If the host was legitimately rebuilt, clear the recorded key or pass host_key_fingerprint",
					hostname, fp, pinned)
			}
			return nil
		}
		// First contact. Record it so the next deploy to this address is
		// checked against it.
		mu.Lock()
		recorded = fp
		mu.Unlock()
		if d.store != nil {
			if err := d.store.SetSetting(settingKey, fp); err != nil {
				return fmt.Errorf("could not record the host key for %s: %w", hostname, err)
			}
		}
		return nil
	}

	return cb, func() string {
		mu.Lock()
		defer mu.Unlock()
		return recorded
	}, nil
}
