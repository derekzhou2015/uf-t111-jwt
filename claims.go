package jwt

// Claims represent any form of a JWT Claims Set according to
// https://datatracker.ietf.org/doc/html/rfc7519#section-4. In order to have a
// common basis for validation, it is required that an implementation is able to
// supply at least the claim names provided in
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1 namely `exp`,
// `iat`, `nbf`, `iss`, `sub` and `aud`.
//
// # Absent claims and explicit null values
//
// The getters have to distinguish these two cases for validation to be
// meaningful, because they lead to different errors:
//
//   - An absent claim returns the zero value without an error. If a validator
//     requires that claim, it fails with [ErrTokenRequiredClaimMissing].
//   - A claim that is present but cannot be interpreted, such as an explicit
//     JSON null or a value of the wrong JSON type, returns an error wrapping
//     [ErrInvalidType]. This holds even if the validator does not require the
//     claim: a present-but-unusable `exp` must not turn into a token that never
//     expires.
//
// Both containers shipped with this package implement this the same way, so a
// token is classified identically no matter which one it is decoded into. The
// `aud` claim is the single documented exception: a null audience means "no
// audience" (an absent `aud`) rather than an error, matching
// [ClaimStrings.UnmarshalJSON].
type Claims interface {
	GetExpirationTime() (*NumericDate, error)
	GetIssuedAt() (*NumericDate, error)
	GetNotBefore() (*NumericDate, error)
	GetIssuer() (string, error)
	GetSubject() (string, error)
	GetAudience() (ClaimStrings, error)
}
