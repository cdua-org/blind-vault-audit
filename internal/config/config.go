// Package config contains global application configuration and constants.
package config

// API endpoints used across the application.
const (
	Endpoint2FA      = "https://2fa.directory/api/v3/all.json"
	EndpointPK       = "https://passkeys-api.2fa.directory/v1/all.json"
	EndpointBreaches = "https://haveibeenpwned.com/api/v3/breaches"
)

// EndpointUpdate is the endpoint for the latest release.
var EndpointUpdate = "https://api.github.com/repos/cdua-org/blind-vault-audit/releases/latest"

// Modes supported by the application.
const (
	ModeBreach = "breach"
	ModeMFA    = "mfa"
	ModeUpdate = "update"
)

// Field types.
const (
	FieldTypePassword = "password"
	FieldTypeUsername = "username"
	FieldTypeURL      = "url"
	FieldTypeTOTP     = "totp"
)
