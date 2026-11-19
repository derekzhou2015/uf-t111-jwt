package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// This file implements the handling of explicit JSON null values in registered
// claims. The semantics are described on the [Claims] interface; in short, an
// explicit null makes a claim *present but unusable* (reported as
// [ErrInvalidType]), while an absent claim is *missing* (reported as
// [ErrTokenRequiredClaimMissing] when a validator requires it). The `aud`
// claim is the documented exception and keeps its existing "no audience"
// meaning.
//
// For [MapClaims] the distinction needs no extra bookkeeping, because the map
// still holds the nil value after decoding. For [RegisteredClaims] and types
// embedding it, the struct only holds zero values after decoding, so the
// parser records which registered claims were explicitly null while the raw
// payload is still available.

// Null-bit mask for registered claims that are not [ClaimStrings]. The
// `aud` claim needs no bit: [RegisteredClaims.GetAudience] returns a nil
// ClaimStrings both when aud is absent and when it is explicitly null, which is
// the already documented behaviour for that claim.
const (
	nullClaimIss uint8 = 1 << iota
	nullClaimSub
	nullClaimExp
	nullClaimNbf
	nullClaimIat
)

// nullClaimBits maps a registered claim name to its bit in the mask returned by
// [detectExplicitNullClaims].
var nullClaimBits = map[string]uint8{
	"iss": nullClaimIss,
	"sub": nullClaimSub,
	"exp": nullClaimExp,
	"nbf": nullClaimNbf,
	"iat": nullClaimIat,
}

// explicitNullClaims is implemented by claim types that are able to record
// which registered claims were present as an explicit JSON null. It is set by
// the [Parser] right after decoding the claims payload.
//
// [RegisteredClaims] implements it, and therefore so does any custom claims
// type that embeds [RegisteredClaims] by value and is passed as a pointer.
// Claim types that implement the [Claims] interface from scratch cannot
// distinguish an explicit null from an absent claim and decide the meaning of
// a zero value themselves.
type explicitNullClaims interface {
	setExplicitNullClaims(mask uint8)
}

// detectExplicitNullClaims returns a mask of the registered claims that appear
// as an explicit JSON null in the claims payload. It returns zero if there are
// none.
//
// The payload is only decoded a second time when it contains the substring
// "null" at all, so the common case stays cheap. A payload that is not a JSON
// object (for example, a bare null) yields zero; decoding of such a payload
// either fails afterwards or leaves all claims absent.
func detectExplicitNullClaims(claimBytes []byte) (mask uint8) {
	if !bytes.Contains(claimBytes, []byte("null")) {
		return 0
	}

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
// is classified the same way regardless of the container it is decoded into.
func invalidClaimError(name string) error {
	return newError(fmt.Sprintf("%s is invalid", name), ErrInvalidType)
}

// errorIfNull reports an explicit JSON null for the named claim, if the mask
// recorded one. The value is returned unchanged otherwise, so callers can keep
// returning the struct field as before.
func errorIfNull(mask, bit uint8, claim string) error {
	if mask&bit != 0 {
		return invalidClaimError(claim)
	}

	return nil
}
