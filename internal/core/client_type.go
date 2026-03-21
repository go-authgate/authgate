package core

// ClientType represents the OAuth 2.0 client type.
type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

// String returns the string representation of the ClientType.
func (ct ClientType) String() string { return string(ct) }

// IsValid reports whether the ClientType is a known value.
func (ct ClientType) IsValid() bool {
	switch ct {
	case ClientTypeConfidential, ClientTypePublic:
		return true
	default:
		return false
	}
}

// OrDefault returns the ClientType if valid, otherwise ClientTypeConfidential.
func (ct ClientType) OrDefault() ClientType {
	if ct.IsValid() {
		return ct
	}
	return ClientTypeConfidential
}

// NormalizeClientType converts a raw string to a ClientType.
// Returns ClientTypeConfidential for any unrecognized value.
func NormalizeClientType(raw string) ClientType {
	ct := ClientType(raw)
	if ct.IsValid() {
		return ct
	}
	return ClientTypeConfidential
}
