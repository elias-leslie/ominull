package response

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func routineTestKey(t *testing.T) (*ecdsa.PrivateKey, []byte, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	xy, err := RoutineKeyXY(string(p))
	if err != nil {
		t.Fatal(err)
	}
	return k, p, xy
}

func routineSign(t *testing.T, k *ecdsa.PrivateKey, msg string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(msg))
	sig, err := ecdsa.SignASN1(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// The release key signs which routine keys exist, in one strict form; a
// routine key then verifies release statements, and nothing else signs the
// list.
func TestRoutineKeysStatement(t *testing.T) {
	rel, relPEM, _ := routineTestKey(t)
	rk1, _, xy1 := routineTestKey(t)
	_, _, xy2 := routineTestKey(t)
	line, err := FormatRoutineKeyList([]RoutineKey{{"ffff000000000000", xy2}, {"0123456789abcdef", xy1}})
	if err != nil || line != "0123456789abcdef:"+xy1+",ffff000000000000:"+xy2 {
		t.Fatalf("keys line: %v %q", err, line)
	}
	stmt, err := RoutineKeysStatement(3, line)
	if err != nil || stmt != "OMINULL-ROUTINE-KEYS-V1\nepoch=3\nkeys="+line+"\n" {
		t.Fatalf("statement: %v %q", err, stmt)
	}
	if p, _ := RoutineKeyPEM(xy1); p == nil {
		t.Fatal("pem")
	} else if back, _ := RoutineKeyXY(string(p)); back != xy1 {
		t.Fatal("PEM round trip")
	}
	signed := &RoutineKeys{Epoch: 3, Keys: line, Sig: base64.StdEncoding.EncodeToString(routineSign(t, rel, stmt))}
	keys, err := VerifyRoutineKeys(relPEM, signed)
	if err != nil || len(keys) != 2 {
		t.Fatalf("verify: %v %v", err, keys)
	}
	byRoutine := &RoutineKeys{Epoch: 3, Keys: line, Sig: base64.StdEncoding.EncodeToString(routineSign(t, rk1, stmt))}
	if _, err := VerifyRoutineKeys(relPEM, byRoutine); err == nil {
		t.Fatal("a routine key signed its own list")
	}
	for _, bad := range []string{
		"ffff000000000000:" + xy2 + ",0123456789abcdef:" + xy1, // unsorted
		"0123456789ABCDEF:" + xy1,                              // upper case
		"0123456789abcdef:" + strings.ToUpper(xy1),
		"0123456789abcde:" + xy1,                               // short id
		"0123456789abcdef: " + xy1,                             // space
		"0123456789abcdef:" + xy1 + ",0123456789abcdef:" + xy1, // duplicate
		"0123456789abcdef:" + strings.Repeat("ab", 64),         // not on the curve
	} {
		if _, err := ParseRoutineKeyList(bad); err == nil {
			t.Errorf("accepted %q", bad[:24])
		}
	}
	var five []RoutineKey
	for _, id := range []string{"1000000000000000", "2000000000000000", "3000000000000000", "4000000000000000", "5000000000000000"} {
		five = append(five, RoutineKey{id, xy1})
	}
	if _, err := FormatRoutineKeyList(five); err == nil {
		t.Fatal("five keys accepted")
	}
	if s, err := RoutineKeysStatement(4, ""); err != nil || s != "OMINULL-ROUTINE-KEYS-V1\nepoch=4\nkeys=\n" {
		t.Fatalf("empty list revokes: %v %q", err, s)
	}
	if _, err := RoutineKeysStatement(0, line); err == nil {
		t.Fatal("epoch 0 accepted")
	}
	msg := ReleaseStatement("ominull-agent_1.2.3_amd64.deb", "1.2.3", strings.Repeat("a", 64))
	if who, err := VerifyReleaseWithRoutine(relPEM, keys, []byte(msg), routineSign(t, rk1, msg)); err != nil || who != "routine:0123456789abcdef" {
		t.Fatalf("routine signer: %v %q", err, who)
	}
	if who, err := VerifyReleaseWithRoutine(relPEM, keys, []byte(msg), routineSign(t, rel, msg)); err != nil || who != "release" {
		t.Fatalf("release signer: %v %q", err, who)
	}
	other, _, _ := routineTestKey(t)
	if _, err := VerifyReleaseWithRoutine(relPEM, keys, []byte(msg), routineSign(t, other, msg)); err == nil {
		t.Fatal("an unlisted key verified")
	}
}
