package response

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Routine release keys: a second kind of release key, which Nightshift opens
// only inside the owner's work session with signing on. Agents and the hub
// accept one only for an agent package's signature and its
// OMINULL-RELEASE-V1 statement, never for trust bundles, host authority,
// rotation or another routine-keys statement. The pinned release key (the
// tap key) signs which routine keys exist, in RoutineKeysStatement;
// agents rebuild it byte for byte (agent_trust.h).
const (
	RoutineKeysMax    = 4
	routineSPKIPrefix = "3059301306072a8648ce3d020106082a8648ce3d030107034200"
)

var (
	routineIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
	routineXYRe = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// RoutineKey is one routine release key: its 16-hex id and its raw P-256
// public point X||Y in lower-case hex.
type RoutineKey struct {
	ID string `json:"id"`
	XY string `json:"xy"`
}

// RoutineKeys is the signed list as agents receive it in the heartbeat:
// Keys exactly as in the statement, Sig the release key's base64 DER
// signature over RoutineKeysStatement.
type RoutineKeys struct {
	Epoch int64  `json:"epoch"`
	Keys  string `json:"keys"`
	Sig   string `json:"sig"`
}

// FormatRoutineKeyList is the statement's keys line: id:xy entries sorted by
// id, comma separated, after checking each.
func FormatRoutineKeyList(keys []RoutineKey) (string, error) {
	if len(keys) > RoutineKeysMax {
		return "", fmt.Errorf("at most %d routine keys", RoutineKeysMax)
	}
	sorted := append([]RoutineKey(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	parts := make([]string, 0, len(sorted))
	for i, k := range sorted {
		if !routineIDRe.MatchString(k.ID) || !routineXYRe.MatchString(k.XY) {
			return "", fmt.Errorf("routine key %q: id is 16 lower-case hex, the key 128 lower-case hex (P-256 X||Y)", k.ID)
		}
		if i > 0 && sorted[i-1].ID == k.ID {
			return "", fmt.Errorf("routine key %s listed twice", k.ID)
		}
		if _, err := routinePublicKey(k.XY); err != nil {
			return "", fmt.Errorf("routine key %s: %w", k.ID, err)
		}
		parts = append(parts, k.ID+":"+k.XY)
	}
	return strings.Join(parts, ","), nil
}

// ParseRoutineKeyList reads a keys line strictly: it must be exactly what
// FormatRoutineKeyList makes of its own entries.
func ParseRoutineKeyList(line string) ([]RoutineKey, error) {
	if line == "" {
		return nil, nil
	}
	var keys []RoutineKey
	for _, e := range strings.Split(line, ",") {
		id, xy, ok := strings.Cut(e, ":")
		if !ok {
			return nil, errors.New("routine key entry is id:xy")
		}
		keys = append(keys, RoutineKey{ID: id, XY: xy})
	}
	again, err := FormatRoutineKeyList(keys)
	if err != nil {
		return nil, err
	}
	if again != line {
		return nil, errors.New("routine keys must be sorted by id, without spaces")
	}
	return keys, nil
}

// RoutineKeysStatement is what the release key signs to say which routine
// keys exist. An empty list revokes them all; a higher epoch replaces.
func RoutineKeysStatement(epoch int64, keysLine string) (string, error) {
	if epoch < 1 {
		return "", errors.New("the routine keys epoch starts at 1")
	}
	if _, err := ParseRoutineKeyList(keysLine); err != nil {
		return "", err
	}
	return "OMINULL-ROUTINE-KEYS-V1\nepoch=" + strconv.FormatInt(epoch, 10) + "\nkeys=" + keysLine + "\n", nil
}

// VerifyRoutineKeys checks the signed list against the pinned release key and
// returns its keys.
func VerifyRoutineKeys(releasePEM []byte, rk *RoutineKeys) ([]RoutineKey, error) {
	if rk == nil {
		return nil, nil
	}
	stmt, err := RoutineKeysStatement(rk.Epoch, rk.Keys)
	if err != nil {
		return nil, err
	}
	der, err := base64.StdEncoding.DecodeString(rk.Sig)
	if err != nil || len(der) == 0 || len(der) > 80 {
		return nil, errors.New("routine keys signature is not base64 DER")
	}
	if err := VerifyReleaseSignature(releasePEM, []byte(stmt), der); err != nil {
		return nil, fmt.Errorf("routine keys are not signed by the release key: %w", err)
	}
	return ParseRoutineKeyList(rk.Keys)
}

func routinePublicKey(xy string) (*ecdsa.PublicKey, error) {
	raw, err := hex.DecodeString(xy)
	if err != nil || len(raw) != 64 {
		return nil, errors.New("not a P-256 point")
	}
	k := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(raw[:32]), Y: new(big.Int).SetBytes(raw[32:])}
	if !k.Curve.IsOnCurve(k.X, k.Y) {
		return nil, errors.New("not a point on P-256")
	}
	return k, nil
}

// RoutineKeyPEM is a routine key as a PEM public key (the form release
// signatures are checked with).
func RoutineKeyPEM(xy string) ([]byte, error) {
	if _, err := routinePublicKey(xy); err != nil {
		return nil, err
	}
	der, _ := hex.DecodeString(routineSPKIPrefix + "04" + xy)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// RoutineKeyXY reads a PEM P-256 public key into the statement's X||Y hex.
func RoutineKeyXY(pubPEM string) (string, error) {
	blk, _ := pem.Decode([]byte(pubPEM))
	if blk == nil {
		return "", errors.New("routine key is not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return "", err
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return "", errors.New("routine key is not P-256")
	}
	out := make([]byte, 64)
	ec.X.FillBytes(out[:32])
	ec.Y.FillBytes(out[32:])
	return hex.EncodeToString(out), nil
}

// VerifyReleaseWithRoutine checks a release signature with the pinned
// release key, then with each routine key; it names the key that verified:
// "release" or "routine:<id>". Only agent packages and their release
// statements may be checked this way.
func VerifyReleaseWithRoutine(releasePEM []byte, routine []RoutineKey, msg, der []byte) (string, error) {
	if err := VerifyReleaseSignature(releasePEM, msg, der); err == nil {
		return "release", nil
	}
	for _, k := range routine {
		p, err := RoutineKeyPEM(k.XY)
		if err != nil {
			continue
		}
		if VerifyReleaseSignature(p, msg, der) == nil {
			return "routine:" + k.ID, nil
		}
	}
	return "", errors.New("signature verifies with neither the release key nor a routine key")
}
