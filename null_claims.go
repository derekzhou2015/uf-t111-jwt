package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// This file implements the handling of explicit JSON nulls in registered
// claims. A claim that is *absent* and a claim that is present with an explicit
// JSON null are different things, and both claim containers shipped by this
// package classify them identically:
//
//   - An absent claim is missing. It fails with
//     [ErrTokenRequiredClaimMissing] only when the validator requires it.
//   - A claim present as an explicit null is present but unusable. It fails
//     with [ErrInvalidType] even when the validator does not require it, so
//     that e.g. `"exp": null` can never become a token that never expires.
//
// [MapClaims] needs no bookkeeping for this: the decoded map still holds the
// nil value, so its accessors see a present-but-unusable claim. [RegisteredClaims]
// and types embedding it only hold zero values after decoding, so the [Parser]
// records which registered claims were explicitly null while the payload is
// still available.
//
// The `aud` claim is the documented exception and is handled by
// [ClaimStrings.UnmarshalJSON]: a null audience means "no audience", which is
// the same as an absent `aud` claim. Claims decoded outside of a [Parser] (for
// example by a direct [encoding/json.Unmarshal] into [RegisteredClaims]) cannot
// be told apart from claims that were never encoded and keep the absent-claim
// behaviour; parsing through this package is what makes the distinction
// available.

// Bit positions for the registered claims that can be reported as an explicit
// JSON null. The `aud` claim deliberately has no bit: a null audience means "no
// audience", not an invalid value.
const (
	nullClaimIss uint8 = 1 << iota
	nullClaimSub
	nullClaimExp
	nullClaimNbf
	nullClaimIat
)

// nullClaimBits maps the registered claim names that may be explicitly null to
// their bit in the mask passed to [explicitNullClaims].
var nullClaimBits = map[string]uint8{
	"iss": nullClaimIss,
	"sub": nullClaimSub,
	"exp": nullClaimExp,
	"nbf": nullClaimNbf,
	"iat": nullClaimIat,
}

// explicitNullClaims is implemented by claims types that can record which
// registered claims were present as an explicit JSON null. The [Parser] calls
// it once, after decoding the claims payload of a token.
//
// [RegisteredClaims] implements it, and therefore so does any custom claims
// type embedding it that is passed to the parser as a pointer. The interface is
// intentionally unexported: claim types that implement [Claims] from scratch
// decide the meaning of their own zero values and need no record.
type explicitNullClaims interface {
	setExplicitNullClaims(mask uint8)
}

// detectExplicitNullClaims returns a mask of the registered claims that appear
// with an explicit JSON null in the claims payload. It returns zero if there
// are none.
//
// The payload is only decoded a second time if it contains the substring
// "null" at all, so the common case stays cheap. A payload that does not decode
// to a JSON object (for example, a bare null) yields zero; decoding of such a
// payload either fails afterwards or leaves every claim absent.
func detectExplicitNullClaims(claimBytes []byte) (mask uint8) {
	if !bytes.Contains(claimBytes, []byte("null")) {
		return 0
	}

	// Decoding into raw messages resolves escaped keys and applies the same
	// last-key-wins rule as decoding into a struct or a map, so the mask always
	// describes the value that ends up in the claims.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(claimBytes, &raw); err != nil {
		return 0
	}

	for name, bit := range nullClaimBits {
		if value, ok := raw[name]; ok && isJSONNull(value) {
			mask |= bit
		}
	}

	return mask
}

// isJSONNull reports whether the raw JSON value is the null literal.
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// invalidClaimError is the error returned for a registered claim that is
// present but cannot be interpreted, such as an explicit JSON null or a value
// of the wrong JSON type. Both claim containers use it, so that the same token
// yields the same error no matter which container it is decoded into.
func invalidClaimError(name string) error {
	return newError(fmt.Sprintf("%s is invalid", name), ErrInvalidType)
}

// errorIfNull returns an [ErrInvalidType] error for the named claim if the mask
// recorded an explicit JSON null for it. It returns nil otherwise, so callers
// can keep returning the struct field as before.
func errorIfNull(mask, bit uint8, claim string) error {
	if mask&bit != 0 {
		return invalidClaimError(claim)
	}

	return nil
}
