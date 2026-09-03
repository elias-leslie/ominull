package scripts

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Script represents the immutable definition of a registered script.
type Script struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	Interpreter   string    `json:"interpreter"` // /bin/sh, /bin/bash, powershell.exe, cmd.exe
	LatestVersion int       `json:"latest_version"`
	Retired       bool      `json:"retired"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ScriptVersion represents an immutable, content-hashed version of a script.
type ScriptVersion struct {
	ScriptID            string    `json:"script_id"`
	Version             int       `json:"version"`
	Source              string    `json:"source"`
	DigestSHA256        string    `json:"digest_sha256"`
	ParameterSchemaJSON string    `json:"parameter_schema_json,omitempty"`
	CreatedBy           string    `json:"created_by"`
	CreatedAt           time.Time `json:"created_at"`
}

// ComputeScriptDigest returns the lowercase hex SHA-256 digest of source code.
func ComputeScriptDigest(source string) string {
	h := sha256.Sum256([]byte(source))
	return hex.EncodeToString(h[:])
}
