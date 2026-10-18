package response

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJobRecordJSONHidesConnectToken(t *testing.T) {
	payload := `{"session_id":"s-1","program":"/bin/sh","connect_token":"SECRET-TOK"}`
	wrapped, _ := json.Marshal(map[string]interface{}{"grant": map[string]string{"grant_id": "g"}, "payload": payload})
	j := JobRecord{ID: "j1", RequestJSON: string(wrapped)}
	out, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "SECRET-TOK") {
		t.Fatalf("token leaked: %s", out)
	}
	var back JobRecord
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(back.RequestJSON, RedactedToken) || !strings.Contains(back.RequestJSON, "s-1") {
		t.Fatalf("redaction lost context: %s", back.RequestJSON)
	}
	if !strings.Contains(j.RequestJSON, "SECRET-TOK") {
		t.Fatal("stored request must keep the token for the endpoint")
	}
}

func TestRedactRequestJSONFallbackAndPassthrough(t *testing.T) {
	if got := RedactRequestJSON(`{"connect_token":"abc","x":1}`); strings.Contains(got, "abc") {
		t.Fatalf("plain: %s", got)
	}
	if got := RedactRequestJSON(`{"mode":"view"}`); got != `{"mode":"view"}` {
		t.Fatalf("changed: %s", got)
	}
}
