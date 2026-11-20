package jwt

// Claims represent any form of a JWT Claims Set according to
// https://datatracker.ietf.org/doc/html/rfc7519#section-4. In order to have a
// common basis for validation, it is required that an implementation is able to
// supply at least the claim names provided in
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1 namely `exp`,
// `iat`, `nbf`, `iss`, `sub` and `aud`.
//
// # Absent claims, explicit nulls and unusable values
//
// The getters distinguish these cases, because they lead to different errors:
//
//   - An absent claim returns the zero value without an error. If a validator
//     requires that claim, it fails with [ErrTokenRequiredClaimMissing].
//   - A claim that is present but cannot be interpreted - an explicit JSON
//     null, or a value of the wrong JSON type - returns an error wrapping
//     [ErrInvalidType]. This holds even when the validator does not require the
//     claim: a present-but-unusable `exp` must not turn into a token that never
//     expires.
//
// Both claim containers shipped with this package behave the same way, so a
// token is classified identically no matter which one it is decoded into. The
// `aud` claim is the single documented exception: a null audience means "no
// audience" (the same as an absent `aud`), matching
// [ClaimStrings.UnmarshalJSON].
//
// The distinction between an absent claim and an explicit null can only be
// carried for claims decoded by this package's [Parser]; claims decoded with
// [encoding/json] directly, or built in Go, have no such record and treat a
// zero value as absent. An implementation of this interface supplies its own
// meaning for zero values.
type Claims interface {
	GetExpirationTime() (*NumericDate, error)
	GetIssuedAt() (*NumericDate, error)
	GetNotBefore() (*NumericDate, error)
	GetIssuer() (string, error)
	GetSubject() (string, error)
	GetAudience() (ClaimStrings, error)
}
