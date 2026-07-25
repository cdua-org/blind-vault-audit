package testdata

import _ "embed"

//go:embed enpass.json
var FixtureEnpassVault []byte

//go:embed 2fa_v1.json
var Fixture2FA []byte

//go:embed passkeys_v1.json
var FixturePasskeys []byte

//go:embed breaches_v1.json
var FixtureBreaches []byte
