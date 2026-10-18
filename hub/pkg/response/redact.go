package response

import (
	"encoding/json"
	"regexp"
)

// connectTokenRE matches a connect_token value in JSON text, in plain or
// escaped (inside a JSON string) form. Fallback for payloads that do not parse.
var connectTokenRE = regexp.MustCompile(`(connect_token\\*"\s*:\s*\\*")[^"\\]*`)

// RedactedToken replaces a connect_token in anything that leaves the hub.
const RedactedToken = "(hidden)"

// RedactRequestJSON hides the one-use connect_token that terminal and screen
// offers carry in a job's request. The stored request keeps it, since the
// endpoint is handed that exact payload in its heartbeat; job reads must not.
func RedactRequestJSON(s string) string {
	if s == "" || !connectTokenRE.MatchString(s) {
		return s
	}
	var wrapped map[string]json.RawMessage
	if json.Unmarshal([]byte(s), &wrapped) == nil {
		if rawPayload, ok := wrapped["payload"]; ok {
			var payload string
			if json.Unmarshal(rawPayload, &payload) == nil {
				red, _ := json.Marshal(connectTokenRE.ReplaceAllString(payload, "${1}"+RedactedToken))
				wrapped["payload"] = red
				if out, err := json.Marshal(wrapped); err == nil {
					return string(out)
				}
			}
		}
	}
	return connectTokenRE.ReplaceAllString(s, "${1}"+RedactedToken)
}

// MarshalJSON keeps the connect_token out of every job read (API, console).
func (j JobRecord) MarshalJSON() ([]byte, error) {
	type plain JobRecord
	p := plain(j)
	p.RequestJSON = RedactRequestJSON(p.RequestJSON)
	return json.Marshal(p)
}
