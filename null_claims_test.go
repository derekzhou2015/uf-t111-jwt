package jwt

import (
	"errors"
	"testing"
	"time"
)

// nullTestKey is a static HS256 key: all fixtures in this file are signed
// offline, without any network access.
var nullTestKey = []byte("null-claims-regression-key")

// nullTestCustomClaims is a custom claims type that embeds RegisteredClaims by
// value, which is the documented way to extend the structured claims.
type nullTestCustomClaims struct {
	Foo string `json:"foo"`
	RegisteredClaims
}

func nullTestKeyfunc(*Token) (any, error) { return nullTestKey, nil }

// signNullTestToken builds a compact HS256 token from claims.
func signNullTestToken(t *testing.T, claims Claims) string {
	t.Helper()

	signed, err := NewWithClaims(SigningMethodHS256, claims).SignedString(nullTestKey)
	if err != nil {
		t.Fatalf("could not sign test token: %v", err)
	}

	return signed
}

// nullTestContainer is one way of decoding the claims of a token.
type nullTestContainer struct {
	name     string
	newClaim func() Claims
}

// nullTestContainers are the two containers shipped by this package plus a
// custom type embedding RegisteredClaims, which must behave like it.
var nullTestContainers = []nullTestContainer{
	{"MapClaims", func() Claims { return MapClaims{} }},
	{"RegisteredClaims", func() Claims { return &RegisteredClaims{} }},
	{"custom embedding RegisteredClaims", func() Claims { return &nullTestCustomClaims{} }},
}

// nullTestOutcome classifies a validation error into the categories this
// package distinguishes for registered claims.
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
	default:
		return "other: " + err.Error()
	}
}

// TestNullClaimContainersConverge is the core regression for the reported
// drift: the same token must be classified identically no matter which claims
// container it is decoded into, and identically through both validation entry
// points (parser validation and a standalone Validator).
func TestNullClaimContainersConverge(t *testing.T) {
	const (
		valid       = "valid"
		invalidType = "invalid-type"
		missing     = "missing"
	)

	allNull := MapClaims{
		"iss": nil,
		"sub": nil,
		"aud": nil,
		"exp": nil,
		"nbf": nil,
		"iat": nil,
	}

	tests := []struct {
		name    string
		payload MapClaims
		opts    []ParserOption
		want    string
	}{
		// A null time claim is present but unusable, never "absent". In
		// particular an exp null must never become a valid, never-expiring
		// token, required or not.
		{"exp null optional", MapClaims{"exp": nil}, nil, invalidType},
		{"exp null required", MapClaims{"exp": nil}, []ParserOption{WithExpirationRequired()}, invalidType},
		{"nbf null optional", MapClaims{"nbf": nil}, nil, invalidType},
		{"nbf null required", MapClaims{"nbf": nil}, []ParserOption{WithNotBeforeRequired()}, invalidType},
		{"iat null not verified", MapClaims{"iat": nil}, nil, valid},
		{"iat null verified", MapClaims{"iat": nil}, []ParserOption{WithIssuedAt()}, invalidType},
		{"iss null not checked", MapClaims{"iss": nil}, nil, valid},
		{"iss null expected", MapClaims{"iss": nil}, []ParserOption{WithIssuer("trusted")}, invalidType},
		{"sub null not checked", MapClaims{"sub": nil}, nil, valid},
		{"sub null expected", MapClaims{"sub": nil}, []ParserOption{WithSubject("alice")}, invalidType},
		// aud keeps its documented meaning: null means "no audience", so an
		// expected audience is reported as a missing claim, not a type error.
		{"aud null not checked", MapClaims{"aud": nil}, nil, valid},
		{"aud null expected", MapClaims{"aud": nil}, []ParserOption{WithAudience("example.com")}, missing},
		{"aud null all expected", MapClaims{"aud": nil}, []ParserOption{WithAllAudiences("example.com")}, missing},
		{"all null", allNull, nil, invalidType},

		// Control: genuinely absent claims stay "missing", which is what keeps
		// the two categories distinct after the unification.
		{"exp missing required", MapClaims{}, []ParserOption{WithExpirationRequired()}, missing},
		{"nbf missing required", MapClaims{}, []ParserOption{WithNotBeforeRequired()}, missing},
		{"iss missing expected", MapClaims{}, []ParserOption{WithIssuer("trusted")}, missing},
		{"sub missing expected", MapClaims{}, []ParserOption{WithSubject("alice")}, missing},
		{"aud missing expected", MapClaims{}, []ParserOption{WithAudience("example.com")}, missing},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := signNullTestToken(t, tt.payload)

			for _, container := range nullTestContainers {
				t.Run(container.name, func(t *testing.T) {
					// Entry point 1: validation inside the parser.
					parsed, err := NewParser(tt.opts...).ParseWithClaims(tokenString, container.newClaim(), nullTestKeyfunc)
					if got := nullTestOutcome(err); got != tt.want {
						t.Errorf("ParseWithClaims outcome = %s (%v), want %s", got, err, tt.want)
					}
					if parsed == nil {
						t.Fatalf("ParseWithClaims returned no token")
					}

					// Entry point 2: a standalone Validator over the claims that
					// were decoded without validation.
					unverified, _, err := NewParser().ParseUnverified(tokenString, container.newClaim())
					if err != nil {
						t.Fatalf("ParseUnverified failed: %v", err)
					}
					if got := nullTestOutcome(NewValidator(tt.opts...).Validate(unverified.Claims)); got != tt.want {
						t.Errorf("Validator.Validate outcome = %s, want %s", got, tt.want)
					}
				})
			}
		})
	}
}

// TestNullClaimContainersConvergeWithJSONNumber pins the same convergence for
// the WithJSONNumber decoding path, where numbers arrive as json.Number.
func TestNullClaimContainersConvergeWithJSONNumber(t *testing.T) {
	tokenString := signNullTestToken(t, MapClaims{"exp": nil})

	for _, container := range nullTestContainers {
		t.Run(container.name, func(t *testing.T) {
			_, err := NewParser(WithJSONNumber()).ParseWithClaims(tokenString, container.newClaim(), nullTestKeyfunc)
			if !errors.Is(err, ErrInvalidType) {
				t.Fatalf("expected ErrInvalidType for a null exp, got %v", err)
			}
		})
	}
}

// TestNullExpirationNeverValid is a focused fail-closed check for the security
// relevant case: an exp that is present as null must be rejected under every
// option combination that leaves exp unrequired.
func TestNullExpirationNeverValid(t *testing.T) {
	tokenString := signNullTestToken(t, MapClaims{"exp": nil})

	for _, opts := range [][]ParserOption{
		nil,
		{WithLeeway(0)},
		{WithIssuedAt()},
		{WithAudience("example.com")},
		{WithIssuer("trusted")},
		{WithoutClaimsValidation()}, // documented escape hatch, must not validate
	} {
		for _, container := range nullTestContainers {
			_, err := NewParser(opts...).ParseWithClaims(tokenString, container.newClaim(), nullTestKeyfunc)

			skipValidation := false
			for _, opt := range opts {
				p := NewParser()
				opt(p)
				skipValidation = skipValidation || p.skipClaimsValidation
			}

			if skipValidation {
				if err != nil {
					t.Errorf("%s with validation skipped: unexpected error %v", container.name, err)
				}
				continue
			}

			if !errors.Is(err, ErrInvalidType) {
				t.Errorf("%s: expected ErrInvalidType for a null exp, got %v", container.name, err)
			}
		}
	}
}

// TestRegisteredClaimsExplicitNullGetters checks the structured getters
// directly: a recorded null is an invalid type, while a hand-built zero value
// is still simply absent.
func TestRegisteredClaimsExplicitNullGetters(t *testing.T) {
	claims := &RegisteredClaims{
		Issuer:    "trusted",
		Subject:   "alice",
		Audience:  ClaimStrings{"example.com"},
		ExpiresAt: NewNumericDate(time.Now()),
	}
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
	if aud, err := claims.GetAudience(); err != nil || len(aud) != 1 {
		t.Errorf("GetAudience() = %v, %v; want the stored audience and no error", aud, err)
	}

	// Built by hand, without any recorded null, the same claims are fine.
	handBuilt := RegisteredClaims{Issuer: "trusted", Subject: "alice"}
	if _, err := handBuilt.GetIssuer(); err != nil {
		t.Errorf("hand-built GetIssuer() error = %v, want nil", err)
	}
	if _, err := handBuilt.GetSubject(); err != nil {
		t.Errorf("hand-built GetSubject() error = %v, want nil", err)
	}
	if exp, err := handBuilt.GetExpirationTime(); err != nil || exp != nil {
		t.Errorf("hand-built GetExpirationTime() = %v, %v; want nil, nil", exp, err)
	}
}

// TestDetectExplicitNullClaims covers the payload inspection that feeds the
// structured container, including the shortcuts that keep it cheap.
func TestDetectExplicitNullClaims(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    uint8
	}{
		{"empty object", `{}`, 0},
		{"no null", `{"exp":1516239022}`, 0},
		{"null in a string value", `{"note":"a nullable note"}`, 0},
		{"bare null payload", `null`, 0},
		{"invalid JSON", `{"exp":`, 0},
		{"exp", `{"exp":null}`, nullClaimExp},
		{"iss", `{"iss":null}`, nullClaimIss},
		{"sub", `{"sub":null}`, nullClaimSub},
		{"nbf", `{"nbf":null}`, nullClaimNbf},
		{"iat", `{"iat":null}`, nullClaimIat},
		{"aud has no bit", `{"aud":null}`, 0},
		{"multiple", `{"iss":null,"exp":null,"nbf":null}`, nullClaimIss | nullClaimExp | nullClaimNbf},
		{"whitespace around null", `{"exp": null }`, nullClaimExp},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectExplicitNullClaims([]byte(tt.payload)); got != tt.want {
				t.Errorf("detectExplicitNullClaims(%s) = %#02b, want %#02b", tt.payload, got, tt.want)
			}
		})
	}
}
