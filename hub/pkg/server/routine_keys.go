package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"ominull/hub/pkg/response"
)

// Routine release keys (response/routine_keys.go): the pinned release key
// signs which routine keys exist; the hub keeps that signed list, hands it to
// agents in the heartbeat and to the authority with every rollout ask, and
// never decides it itself.
const routineKeysSetting = "routine_release_keys"

type routineKeyInput struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"` // PEM P-256
}

type routineKeysRequest struct {
	Epoch     int64             `json:"epoch"`
	Keys      []routineKeyInput `json:"keys"`
	Signature string            `json:"signature,omitempty"`
}

// routineKeys is the stored list, re-verified against the pinned release key
// on every read (nil when none or when it no longer verifies).
func (s *Server) routineKeys() (*response.RoutineKeys, []response.RoutineKey) {
	raw, _ := s.store.GetSetting(routineKeysSetting)
	if raw == "" {
		return nil, nil
	}
	var rk response.RoutineKeys
	if json.Unmarshal([]byte(raw), &rk) != nil {
		return nil, nil
	}
	keys, err := response.VerifyRoutineKeys(s.releasePublicKey(), &rk)
	if err != nil {
		return nil, nil
	}
	return &rk, keys
}

func (s *Server) routineKeysLine(req *routineKeysRequest) (string, string, error) {
	keys := make([]response.RoutineKey, 0, len(req.Keys))
	for _, k := range req.Keys {
		xy, err := response.RoutineKeyXY(k.PublicKey)
		if err != nil {
			return "", "", fmt.Errorf("routine key %q: %w", k.ID, err)
		}
		keys = append(keys, response.RoutineKey{ID: strings.TrimSpace(k.ID), XY: xy})
	}
	line, err := response.FormatRoutineKeyList(keys)
	if err != nil {
		return "", "", err
	}
	stmt, err := response.RoutineKeysStatement(req.Epoch, line)
	return line, stmt, err
}

// handleRoutineKeys: GET shows the held list; POST stores a new one signed by
// the pinned release key, at a higher epoch than the held one (an empty key
// list revokes every routine key).
func (s *Server) handleRoutineKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rk, keys := s.routineKeys()
		out := map[string]interface{}{"epoch": 0, "keys": []interface{}{}}
		if rk != nil {
			list := make([]map[string]string, 0, len(keys))
			for _, k := range keys {
				p, _ := response.RoutineKeyPEM(k.XY)
				list = append(list, map[string]string{"id": k.ID, "xy": k.XY, "public_key": string(p)})
			}
			out = map[string]interface{}{"epoch": rk.Epoch, "keys": list, "signature": rk.Sig}
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var req routineKeysRequest
		if !decodeStrictBody(w, r, &req) {
			return
		}
		line, stmt, err := s.routineKeysLine(&req)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		rk := &response.RoutineKeys{Epoch: req.Epoch, Keys: line, Sig: strings.TrimSpace(req.Signature)}
		if _, err := response.VerifyRoutineKeys(s.releasePublicKey(), rk); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if held, _ := s.routineKeys(); held != nil {
			if req.Epoch < held.Epoch || (req.Epoch == held.Epoch && line != held.Keys) {
				writeJSONError(w, http.StatusConflict, fmt.Sprintf("the held routine keys are at epoch %d; a new list needs a higher epoch", held.Epoch))
				return
			}
		}
		raw, _ := json.Marshal(rk)
		if err := s.store.SetSetting(routineKeysSetting, string(raw)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(r, "ROUTINE_KEYS_SIGNED", "", fmt.Sprintf("release-key signed routine release keys stored (epoch %d, %d key(s)): agents accept them for agent packages only", req.Epoch, len(req.Keys)))
		writeJSON(w, http.StatusOK, map[string]interface{}{"epoch": req.Epoch, "keys": len(req.Keys), "statement": stmt})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleRoutineKeysStatement returns the exact bytes the release key signs
// for a proposed list.
func (s *Server) handleRoutineKeysStatement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req routineKeysRequest
	if !decodeStrictBody(w, r, &req) {
		return
	}
	line, stmt, err := s.routineKeysLine(&req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"epoch": req.Epoch, "keys": line, "statement": stmt})
}

func decodeStrictBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return false
	}
	return true
}

func requireAdminRole(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Role") != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin role required")
			return
		}
		next(w, r)
	}
}

// releaseSignedByRoutine says a published agent release's statements verify
// only with a routine key: it then rolls out canaries first.
func (s *Server) releaseSignedByRoutine(version string) bool {
	_, keys := s.routineKeys()
	if len(keys) == 0 {
		return false
	}
	for _, pkg := range []string{"deb", "windows-native"} {
		name, sha, ok := s.signedAgentPackage(version, pkg)
		if !ok {
			return false
		}
		sig, err := os.ReadFile(filepath.Join(s.binaryDir, name+".release.sig"))
		if err != nil {
			return false
		}
		signer, err := response.VerifyReleaseWithRoutine(s.releasePublicKey(), keys, []byte(response.ReleaseStatement(name, version, sha)), sig)
		if err == nil && signer != "release" {
			return true
		}
	}
	return false
}
