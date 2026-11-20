package jwt

import (
	"encoding/json"
	"errors"
	"testing"
)

// nullTestKey is a static HS256 key: every fixture in this file is signed
// offline, without any network access.
var nullTestKey = []byte("null-claims-regression-key")

func nullTestKeyfunc(*Token) (any, error) { return nullTestKey, nil }

// signNullTestToken returns a compact HS256 token for the given payload.
func signNullTestToken(t *testing.T, payload string) string {
	t.Helper()

	method := SigningMethodHS256
	token := New(method, nil)
	signingString := token.EncodeSegment([]byte(`{"alg":"HS256","typ":"JWT"}`)) +
		"." + token.EncodeSegment([]byte(payload))
	signature, err := method.Sign(signingString, nullTestKey)
	if err != nil {
		t.Fatalf("could not sign test token: %v", err)
	}

	return signingString + "." + token.EncodeSegment(signature)
}

// nullTestCustomClaims embeds RegisteredClaims by value, which is the
// documented way to extend the structured claims.
type nullTestCustomClaims struct {
	Foo string `json:"foo"`
	RegisteredClaims
}

// nullTestEmbeddedPtrClaims embeds *RegisteredClaims, the other documented
// shape. The embedded pointer must be allocated before use, as ParseWithClaims
// documents, which is what nullTestContainers does.
type nullTestEmbeddedPtrClaims struct {
	Foo string `json:"foo"`
	*RegisteredClaims
}

// nullTestContainer is one way of decoding a token's claims.
type nullTestContainer struct {
	name  string
	claim func() Claims
}

// nullTestContainers are the two containers shipped by this package plus both
// documented embedding shapes for RegisteredClaims. The pointer embedding is
// pre-allocated, as ParseWithClaims requires for that shape.
var nullTestContainers = []nullTestContainer{
	{"MapClaims", func() Claims { return MapClaims{} }},
	{"*RegisteredClaims", func() Claims { return &RegisteredClaims{} }},
	{"custom embedding RegisteredClaims", func() Claims { return &nullTestCustomClaims{} }},
	{"custom embedding *RegisteredClaims", func() Claims {
		return &nullTestEmbeddedPtrClaims{RegisteredClaims: &RegisteredClaims{}}
	}},
}

// nullTestOutcome classifies an error into the categories this package
// distinguishes for registered claims.
func nullTestOutcome(err error) string {
	switch {
	case err == nil:
		return "valid"
	case errors.Is(err, ErrInvalidType):
		return "invalid-type"
	case errors.Is(err, ErrTokenRequiredClaimMissing):
		return "missing"
	case errors.Is(err, ErrTokenExpired):
		return "expired"
	case errors.Is(err, ErrTokenNotValidYet):
		return "not-yet-valid"
	case errors.Is(err, ErrTokenInvalidIssuer):
		return "invalid-issuer"
	case errors.Is(err, ErrTokenInvalidSubject):
		return "invalid-subject"
	case errors.Is(err, ErrTokenInvalidAudience):
		return "invalid-audience"
	case errors.Is(err, ErrTokenMalformed):
		return "malformed"
	default:
		return "other: " + err.Error()
	}
}

// TestNullClaimSemanticsConverge is the core regression for the reported drift:
// the same token must be classified identically no matter which claims
// container it is decoded into, and identically through both validation entry
// points (parser validation and a standalone Validator over the claims decoded
// by ParseUnverified).
func TestNullClaimSemanticsConverge(t *testing.T) {
	const (
		valid       = "valid"
		invalidType = "invalid-type"
		missing     = "missing"
	)

	allNull := `{"iss":null,"sub":null,"aud":null,"exp":null,"nbf":null,"iat":null}`

	tests := []struct {
		name    string
		payload string
		opts    []ParserOption
		want    string
	}{
		// A null time claim is present but unusable, never "absent". In
		// particular an exp null must never become a valid, never-expiring
		// token, whether or not the claim is required.
		{"exp null optional", `{"exp":null}`, nil, invalidType},
		{"exp null required", `{"exp":null}`, []ParserOption{WithExpirationRequired()}, invalidType},
		{"nbf null optional", `{"nbf":null}`, nil, invalidType},
		{"nbf null required", `{"nbf":null}`, []ParserOption{WithNotBeforeRequired()}, invalidType},
		{"iat null not verified", `{"iat":null}`, nil, valid},
		{"iat null verified", `{"iat":null}`, []ParserOption{WithIssuedAt()}, invalidType},
		{"iss null not checked", `{"iss":null}`, nil, valid},
		{"iss null expected", `{"iss":null}`, []ParserOption{WithIssuer("trusted")}, invalidType},
		{"sub null not checked", `{"sub":null}`, nil, valid},
		{"sub null expected", `{"sub":null}`, []ParserOption{WithSubject("alice")}, invalidType},
		{"all null", allNull, nil, invalidType},

		// aud keeps its settled meaning: null means "no audience", so an
		// expected audience is reported as a missing claim, not a type error.
		{"aud null not checked", `{"aud":null}`, nil, valid},
		{"aud null expected", `{"aud":null}`, []ParserOption{WithAudience("example.com")}, missing},
		{"aud null all expected", `{"aud":null}`, []ParserOption{WithAllAudiences("example.com")}, missing},

		// Non-null values are a separate axis: they are rejected one layer
		// earlier by the structured containers (the JSON decode fails, so the
		// parser reports ErrTokenMalformed) while MapClaims reports
		// ErrInvalidType. Both reject; only the error taxonomy differs, and that
		// behaviour is unchanged by this work.
		{"exp string", `{"exp":"foo"}`, nil, "malformed-or-invalid-type"},
		{"iss number", `{"iss":1}`, []ParserOption{WithIssuer("trusted")}, "malformed-or-invalid-type"},
		{"aud array with null element", `{"aud":[null]}`, []ParserOption{WithAudience("example.com")}, "malformed-or-invalid-type"},
		// Control: genuinely absent claims stay "missing", which is what keeps
		// the two categories distinct after the unification.
		{"exp missing required", `{}`, []ParserOption{WithExpirationRequired()}, missing},
		{"nbf missing required", `{}`, []ParserOption{WithNotBeforeRequired()}, missing},
		{"iss missing expected", `{}`, []ParserOption{WithIssuer("trusted")}, missing},
		{"sub missing expected", `{}`, []ParserOption{WithSubject("alice")}, missing},
		{"aud missing expected", `{}`, []ParserOption{WithAudience("example.com")}, missing},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := signNullTestToken(t, tt.payload)

			for _, container := range nullTestContainers {
				// Entry point 1: validation inside the parser.
				_, err := NewParser(tt.opts...).ParseWithClaims(tokenString, container.claim(), nullTestKeyfunc)
				if got := nullTestOutcome(err); !nullTestMatches(got, tt.want) {
					t.Errorf("%s: ParseWithClaims outcome = %s (%v), want %s", container.name, got, err, tt.want)
				}

				// Non-null unusable values fail at JSON decoding, before any
				// validation or unverified parsing can succeed. Skip the second
				// entry point for them.
				if tt.want == "malformed-or-invalid-type" {
					continue
				}

				// Entry point 2: a standalone Validator over claims decoded
				// without validation. The recorded nulls must survive
				// ParseUnverified, or the two entry points would disagree.
				unverified, _, err := NewParser().ParseUnverified(tokenString, container.claim())
				if err != nil {
					t.Fatalf("%s: ParseUnverified failed: %v", container.name, err)
				}
				if got := nullTestOutcome(NewValidator(tt.opts...).Validate(unverified.Claims)); !nullTestMatches(got, tt.want) {
					t.Errorf("%s: Validator.Validate outcome = %s, want %s", container.name, got, tt.want)
				}
			}
		})
	}
}

// nullTestMatches reports whether the actual outcome satisfies the expectation.
func nullTestMatches(got, want string) bool {
	if want == "malformed-or-invalid-type" {
		return got == "malformed" || got == "invalid-type"
	}

	return got == want
}

// TestNullClaimSemanticsConvergeWithJSONNumber pins the same convergence for
// the WithJSONNumber decoding path, where numbers arrive as json.Number.
func TestNullClaimSemanticsConvergeWithJSONNumber(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{"exp null", `{"exp":null}`, "invalid-type"},
		{"exp number", `{"exp":0}`, "expired"},
		{"exp missing required", `{}`, "missing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := signNullTestToken(t, tt.payload)

			for _, container := range nullTestContainers {
				opts := []ParserOption{WithJSONNumber(), WithExpirationRequired()}
				_, err := NewParser(opts...).ParseWithClaims(tokenString, container.claim(), nullTestKeyfunc)
				if got := nullTestOutcome(err); got != tt.want {
					t.Errorf("%s: outcome = %s (%v), want %s", container.name, got, err, tt.want)
				}
			}
		})
	}
}

// TestNullExpirationNeverValid is a focused fail-closed check for the security
// relevant case: an exp that is present as null must be rejected under every
// option combination that still validates claims.
func TestNullExpirationNeverValid(t *testing.T) {
	tokenString := signNullTestToken(t, `{"exp":null}`)

	optionSets := map[string][]ParserOption{
		"default":      nil,
		"leeway":       {WithLeeway(0)},
		"issued at":    {WithIssuedAt()},
		"audience":     {WithAudience("example.com")},
		"issuer":       {WithIssuer("trusted")},
		"exp required": {WithExpirationRequired()},
	}

	for name, opts := range optionSets {
		t.Run(name, func(t *testing.T) {
			for _, container := range nullTestContainers {
				_, err := NewParser(opts...).ParseWithClaims(tokenString, container.claim(), nullTestKeyfunc)
				if !errors.Is(err, ErrInvalidType) {
					t.Errorf("%s: expected ErrInvalidType for a null exp, got %v", container.name, err)
				}
			}
		})
	}

	// WithoutClaimsValidation is the documented escape hatch and must keep
	// skipping validation entirely.
	for _, container := range nullTestContainers {
		if _, err := NewParser(WithoutClaimsValidation()).ParseWithClaims(tokenString, container.claim(), nullTestKeyfunc); err != nil {
			t.Errorf("%s: validation skipped, unexpected error %v", container.name, err)
		}
	}
}

// TestNullClaimAbsentVsNull verifies that recording nulls did not collapse the
// distinction the semantics are built on: an explicit null is a type error even
// when the claim is optional, while an absent claim is simply missing.
func TestNullClaimAbsentVsNull(t *testing.T) {
	nullToken := signNullTestToken(t, `{"exp":null}`)
	absentToken := signNullTestToken(t, `{}`)

	for _, container := range nullTestContainers {
		t.Run(container.name, func(t *testing.T) {
			// Optional claims: null fails, absent passes.
			if _, err := NewParser().ParseWithClaims(nullToken, container.claim(), nullTestKeyfunc); !errors.Is(err, ErrInvalidType) {
				t.Errorf("null exp: error = %v, want ErrInvalidType", err)
			}
			if _, err := NewParser().ParseWithClaims(absentToken, container.claim(), nullTestKeyfunc); err != nil {
				t.Errorf("absent exp: unexpected error %v", err)
			}

			// Required claims: null is a type error, absent is a missing claim.
			if _, err := NewParser(WithExpirationRequired()).ParseWithClaims(nullToken, container.claim(), nullTestKeyfunc); !errors.Is(err, ErrInvalidType) {
				t.Errorf("required null exp: error = %v, want ErrInvalidType", err)
			}
			if _, err := NewParser(WithExpirationRequired()).ParseWithClaims(absentToken, container.claim(), nullTestKeyfunc); !errors.Is(err, ErrTokenRequiredClaimMissing) {
				t.Errorf("required absent exp: error = %v, want ErrTokenRequiredClaimMissing", err)
			}
		})
	}
}

// TestRegisteredClaimsNullGetters checks the structured getters directly: a
// recorded null is an invalid type, while a hand-built zero value is still
// simply absent.
func TestRegisteredClaimsNullGetters(t *testing.T) {
	claims := &RegisteredClaims{}
	claims.setExplicitNullClaims(nullClaimIss | nullClaimSub | nullClaimExp | nullClaimNbf | nullClaimIat)

	if _, err := claims.GetIssuer(); !errors.Is(err, ErrInvalidType) {
		t.Errorf("GetIssuer() error = %v, want ErrInvalidType", err)
	}
	if _, err := claims.GetSubject(); !errors.Is(err, ErrInvalidType) {
		t.Errorf("GetSubject() error = %v, want ErrInvalidType", err)
	}
	if _, err := claims.GetExpirationTime(); !errors.Is(err, ErrInvalidType) {
		t.Errorf("GetExpirationTime() error = %v, want ErrInvalidType", err)
	}
	if _, err := claims.GetNotBefore(); !errors.Is(err, ErrInvalidType) {
		t.Errorf("GetNotBefore() error = %v, want ErrInvalidType", err)
	}
	if _, err := claims.GetIssuedAt(); !errors.Is(err, ErrInvalidType) {
		t.Errorf("GetIssuedAt() error = %v, want ErrInvalidType", err)
	}

	// aud is the documented exception and stays a non-error.
	if aud, err := claims.GetAudience(); err != nil || len(aud) != 0 {
		t.Errorf("GetAudience() = %v, %v; want no audience and no error", aud, err)
	}

	// Built by hand, without any recorded null, the same claims are absent.
	handBuilt := RegisteredClaims{}
	if _, err := handBuilt.GetIssuer(); err != nil {
		t.Errorf("hand-built GetIssuer() error = %v, want nil", err)
	}
	if _, err := handBuilt.GetSubject(); err != nil {
		t.Errorf("hand-built GetSubject() error = %v, want nil", err)
	}
	for name, get := range map[string]func() (*NumericDate, error){
		"exp": handBuilt.GetExpirationTime,
		"nbf": handBuilt.GetNotBefore,
		"iat": handBuilt.GetIssuedAt,
	} {
		if date, err := get(); err != nil || date != nil {
			t.Errorf("hand-built %s: got (%v, %v), want (nil, nil)", name, date, err)
		}
	}
}

// TestRegisteredClaimsNullNotMarshaled pins that the null record is internal:
// it never leaks into the JSON representation, so re-signing a parsed claim set
// does not invent a claim value.
func TestRegisteredClaimsNullNotMarshaled(t *testing.T) {
	claims := &RegisteredClaims{}
	claims.setExplicitNullClaims(nullClaimIss | nullClaimExp)

	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got, want := string(encoded), "{}"; got != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}
}

// TestNullRecordSurvivesRoundTripOfGetters makes sure the record is also
// honoured when the getters are reached through the value receiver, e.g. via
// the Claims interface implemented by a value rather than a pointer.
func TestNullRecordSurvivesRoundTripOfGetters(t *testing.T) {
	parsed := &RegisteredClaims{}
	parsed.setExplicitNullClaims(nullClaimExp)

	var asInterface Claims = *parsed // copy, as a value receiver sees it
	if _, err := asInterface.GetExpirationTime(); !errors.Is(err, ErrInvalidType) {
		t.Errorf("GetExpirationTime() through interface = %v, want ErrInvalidType", err)
	}
	if err := NewValidator().Validate(*parsed); !errors.Is(err, ErrInvalidType) {
		t.Errorf("Validate() = %v, want ErrInvalidType", err)
	}
}

// TestDetectExplicitNullClaims covers the payload inspection that feeds the
// structured container, including the shortcuts that keep it cheap and the
// decoding rules that must agree with encoding/json.
func TestDetectExplicitNullClaims(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    uint8
	}{
		{"empty object", `{}`, 0},
		{"no null", `{"exp":1516239022}`, 0},
		{"null substring in a string value", `{"note":"a nullable note"}`, 0},
		{"bare null payload", `null`, 0},
		{"non-object payload", `[null]`, 0},
		{"invalid JSON", `{"exp":`, 0},
		{"exp", `{"exp":null}`, nullClaimExp},
		{"iss", `{"iss":null}`, nullClaimIss},
		{"sub", `{"sub":null}`, nullClaimSub},
		{"nbf", `{"nbf":null}`, nullClaimNbf},
		{"iat", `{"iat":null}`, nullClaimIat},
		{"aud has no bit", `{"aud":null}`, 0},
		{"multiple", `{"iss":null,"exp":null,"nbf":null}`, nullClaimIss | nullClaimExp | nullClaimNbf},
		{"whitespace around null", `{"exp": null }`, nullClaimExp},
		{"escaped key", "{\"ex\\u0070\":null}", nullClaimExp},
		{"case variant is a different key", `{"EXP":null}`, 0},
		{"duplicate keys, null last", `{"exp":123,"exp":null}`, nullClaimExp},
		{"duplicate keys, null first", `{"exp":null,"exp":123}`, 0},
		{"null nested in an object", `{"other":{"exp":null}}`, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectExplicitNullClaims([]byte(tt.payload)); got != tt.want {
				t.Errorf("detectExplicitNullClaims(%s) = %#02b, want %#02b", tt.payload, got, tt.want)
			}
		})
	}
}

// TestDetectExplicitNullClaimsMatchesDecoding cross-checks the mask against
// what encoding/json actually stores for each container. Whenever a claim is
// null, the structured container ends up with a zero value that is
// indistinguishable from absent; the mask is what restores the difference. If
// the two ever disagree, the containers would diverge again.
func TestDetectExplicitNullClaimsMatchesDecoding(t *testing.T) {
	payloads := []string{
		`{}`,
		`{"exp":null}`,
		`{"nbf":null}`,
		`{"iat":null}`,
		`{"iss":null}`,
		`{"sub":null}`,
		`{"exp":null,"iss":"x"}`,
		`{"exp":0}`,
		`{"exp":123,"exp":null}`,
		`{"exp":null,"exp":123}`,
		"{\"ex\\u0070\":null}",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			mask := detectExplicitNullClaims([]byte(payload))

			var structured RegisteredClaims
			if err := json.Unmarshal([]byte(payload), &structured); err != nil {
				// Payloads that do not decode cannot produce a record either.
				if mask != 0 {
					t.Errorf("mask = %#02b for a payload that does not decode (%v)", mask, err)
				}
				return
			}

			var mapClaims MapClaims
			if err := json.Unmarshal([]byte(payload), &mapClaims); err != nil {
				t.Fatalf("MapClaims decode failed: %v", err)
			}

			// Whenever the mask records a null for a claim, the map must hold an
			// explicit null for it. The reverse does not hold in general (a
			// value-typed null decodes differently), so only this direction is
			// asserted.
			checks := []struct {
				claim string
				bit   uint8
			}{
				{"exp", nullClaimExp},
				{"nbf", nullClaimNbf},
				{"iat", nullClaimIat},
				{"iss", nullClaimIss},
				{"sub", nullClaimSub},
			}
			for _, check := range checks {
				if mask&check.bit == 0 {
					continue
				}
				if value, ok := mapClaims[check.claim]; !ok || value != nil {
					t.Errorf("%s: mask says null but MapClaims has %#v (present=%v)", check.claim, value, ok)
				}
			}
		})
	}
}

// TestNullAudienceClearsPreset pins the aud side of the convergence: a null
// audience means "no audience" even when the caller supplied a default value in
// the claims, which ParseWithClaims explicitly allows. MapClaims drops the key,
// so the structured container must not keep its preset.
func TestNullAudienceClearsPreset(t *testing.T) {
	tokenString := signNullTestToken(t, `{"aud":null}`)

	for _, container := range nullTestContainers {
		t.Run(container.name, func(t *testing.T) {
			claims := container.claim()
			presetAudience(claims, ClaimStrings{"preset.example.com"})

			unverified, _, err := NewParser().ParseUnverified(tokenString, claims)
			if err != nil {
				t.Fatalf("ParseUnverified failed: %v", err)
			}

			aud, err := unverified.Claims.GetAudience()
			if err != nil {
				t.Fatalf("GetAudience() error = %v", err)
			}
			if len(aud) != 0 {
				t.Errorf("GetAudience() = %v, want no audience", aud)
			}

			// With an expected audience, "no audience" is a missing claim, not
			// a match against the preset value.
			_, err = NewParser(WithAudience("preset.example.com")).ParseWithClaims(tokenString, container.claim(), nullTestKeyfunc)
			if !errors.Is(err, ErrTokenRequiredClaimMissing) {
				t.Errorf("expected ErrTokenRequiredClaimMissing, got %v", err)
			}
		})
	}
}

// presetAudience stores a default audience in whichever container is supplied,
// mimicking a caller that pre-populates the claims passed to ParseWithClaims.
func presetAudience(claims Claims, aud ClaimStrings) {
	switch c := claims.(type) {
	case MapClaims:
		c["aud"] = []string(aud)
	case *RegisteredClaims:
		c.Audience = aud
	case *nullTestCustomClaims:
		c.Audience = aud
	case *nullTestEmbeddedPtrClaims:
		c.Audience = aud
	}
}

// TestExplicitNullRecordToleratesNilEmbeddedPointer pins that recording nulls
// does not turn a previously tolerated input into a panic. A custom claims type
// may embed an unallocated *RegisteredClaims; the parser calls the recording
// hook on whatever value it was handed, so the hook must accept a nil receiver.
func TestExplicitNullRecordToleratesNilEmbeddedPointer(t *testing.T) {
	for _, payload := range []string{`{}`, `null`, `{"foo":"bar"}`} {
		t.Run(payload, func(t *testing.T) {
			claims := &nullTestEmbeddedPtrClaims{}
			if claims.RegisteredClaims != nil {
				t.Fatal("test setup: embedded pointer should start unallocated")
			}

			token, _, err := NewParser().ParseUnverified(signNullTestToken(t, payload), claims)
			if err != nil {
				t.Fatalf("ParseUnverified failed: %v", err)
			}
			if token.Claims != claims {
				t.Errorf("token.Claims = %T, want the supplied claims", token.Claims)
			}
			if claims.RegisteredClaims != nil {
				t.Error("the payload has no registered claim, so the embedded pointer should stay nil")
			}
		})
	}
}

// TestNullClaimMaskZeroValue pins the mask constants themselves so that a
// future claim addition cannot silently collide with an existing bit.
func TestNullClaimMaskZeroValue(t *testing.T) {
	bits := []uint8{nullClaimIss, nullClaimSub, nullClaimExp, nullClaimNbf, nullClaimIat}
	seen := uint8(0)
	for _, bit := range bits {
		if bit == 0 || bit&(bit-1) != 0 {
			t.Fatalf("bit %#02b is not a single bit", bit)
		}
		if seen&bit != 0 {
			t.Fatalf("bit %#02b is used twice", bit)
		}
		seen |= bit
	}

	// Every bit in the mask has exactly one registered claim name.
	if len(nullClaimBits) != len(bits) {
		t.Fatalf("nullClaimBits has %d entries, want %d", len(nullClaimBits), len(bits))
	}
	// aud must stay out of the record: null aud means "no audience".
	if _, ok := nullClaimBits["aud"]; ok {
		t.Fatal("aud must not have a null bit; a null audience means no audience")
	}
}
