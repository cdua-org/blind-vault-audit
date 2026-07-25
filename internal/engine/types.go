package engine

// BreachInfo holds details about a compromised domain.
type BreachInfo struct {
	Title       string
	DataClasses []string
	BreachDate  int64
}

// SecurityInfo contains MFA configuration instructions.
type SecurityInfo struct {
	Documentation string
	Notes         string
}

// DataClassPasswords represents the HIBP data class for passwords.
const (
	DataClassPasswords = "Passwords"
)
