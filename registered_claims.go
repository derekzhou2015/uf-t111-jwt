package jwt

// RegisteredClaims are a structured version of the JWT Claims Set,
// restricted to Registered Claim Names, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
//
// This type can be used on its own, but then additional private and
// public claims embedded in the JWT will not be parsed. The typical use-case
// therefore is to embedded this in a user-defined claim type.
//
// See examples for how to use this with your own claim types.
//
// An explicit JSON null for `iss`, `sub`, `exp`, `nbf` or `iat` is recorded
// when the claims are parsed and makes the corresponding getter report
// [ErrInvalidType], so that a null claim is never mistaken for an absent one;
// see the [Claims] interface for the reasoning. The `aud` claim keeps its
// documented "absent or null means no audience" behaviour.
type RegisteredClaims struct {
	// the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`

	// the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience ClaimStrings `json:"aud,omitempty"`

	// the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	ExpiresAt *NumericDate `json:"exp,omitempty"`

	// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore *NumericDate `json:"nbf,omitempty"`

	// the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt *NumericDate `json:"iat,omitempty"`

	// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	ID string `json:"jti,omitempty"`

	// nullClaims records which of the claims above were present as an explicit
	// JSON null in the parsed payload. It is zero for claims that were built in
	// Go rather than parsed, so hand-built claims behave as before, and it is
	// not part of the JSON representation.
	nullClaims uint8
}

// setExplicitNullClaims implements [explicitNullClaims]. It tolerates a nil
// receiver, because a custom claims type may embed an unallocated
// *RegisteredClaims; such claims already require allocation before their
// getters are used, and recording a null must not introduce a new panic.
func (c *RegisteredClaims) setExplicitNullClaims(mask uint8) {
	if c == nil {
		return
	}

	c.nullClaims = mask
}

// GetExpirationTime implements the Claims interface.
func (c RegisteredClaims) GetExpirationTime() (*NumericDate, error) {
	return c.ExpiresAt, errorIfNull(c.nullClaims, nullClaimExp, "exp")
}

// GetNotBefore implements the Claims interface.
func (c RegisteredClaims) GetNotBefore() (*NumericDate, error) {
	return c.NotBefore, errorIfNull(c.nullClaims, nullClaimNbf, "nbf")
}

// GetIssuedAt implements the Claims interface.
func (c RegisteredClaims) GetIssuedAt() (*NumericDate, error) {
	return c.IssuedAt, errorIfNull(c.nullClaims, nullClaimIat, "iat")
}

// GetAudience implements the Claims interface.
func (c RegisteredClaims) GetAudience() (ClaimStrings, error) {
	return c.Audience, nil
}

// GetIssuer implements the Claims interface.
func (c RegisteredClaims) GetIssuer() (string, error) {
	return c.Issuer, errorIfNull(c.nullClaims, nullClaimIss, "iss")
}

// GetSubject implements the Claims interface.
func (c RegisteredClaims) GetSubject() (string, error) {
	return c.Subject, errorIfNull(c.nullClaims, nullClaimSub, "sub")
}
