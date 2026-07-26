// Package config contains global application configuration and constants.
package config

// API endpoints used across the application.
const (
	Endpoint2FA      = "https://2fa.directory/api/v3/all.json"
	EndpointPK       = "https://passkeys-api.2fa.directory/v1/all.json"
	EndpointBreaches = "https://haveibeenpwned.com/api/v3/breaches"
)

// Modes supported by the application.
const (
	ModeBreach = "breach"
	ModeMFA    = "mfa"
)

// Field types.
const (
	FieldTypePassword = "password"
	FieldTypeUsername = "username"
	FieldTypeURL      = "url"
	FieldTypeTOTP     = "totp"
)
