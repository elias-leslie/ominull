package responseauth

import "strings"

// The steward key is its own credential: the hub names its requests
// "steward (steward-key)".
const (
	stewardRequesterSuffix = "(steward-key)"
	stewardRunMax          = 80
)

// IsStewardRequester says whether the hub named this requester as the steward.
func IsStewardRequester(requester string) bool {
	return strings.HasSuffix(requester, stewardRequesterSuffix)
}
