package authn

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTBuildVerify_roundTrip(t *testing.T) {
	a := newFakeAuthn(t, newTestMux())

	token := &Token{Issuer: "google", ID: "user@example.com", DisplayName: "User"}
	jwtStr, expires, err := a.jwtBuild(token)
	if err != nil {
		t.Fatalf("jwtBuild: %v", err)
	}
	if expires.Before(time.Now()) {
		t.Fatal("expected future expiry")
	}

	got, ok := a.jwtVerify(jwtStr)
	if !ok {
		t.Fatal("jwtVerify returned false")
	}
	if got.Issuer != token.Issuer || got.ID != token.ID || got.DisplayName != token.DisplayName {
		t.Fatalf("got %+v, want %+v", got, token)
	}
}

func TestJWTBuildWithTTL_validation(t *testing.T) {
	a := newFakeAuthn(t, newTestMux())
	token := &Token{Issuer: "fake", ID: "user"}

	_, _, err := a.jwtBuildWithTTL(nil, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "token cannot be nil") {
		t.Fatalf("expected nil token error, got %v", err)
	}

	_, _, err = a.jwtBuildWithTTL(token, 0)
	if err == nil || !strings.Contains(err.Error(), "ttl must be positive") {
		t.Fatalf("expected ttl error, got %v", err)
	}
}

func TestJWTVerify_rejectsInvalidTokens(t *testing.T) {
	a := newFakeAuthn(t, newTestMux())

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "garbage", token: "not-a-jwt"},
		{name: "wrong secret", token: mustSignJWT(t, []byte("other-secret"), jwt.MapClaims{"provider": "x", "id": "y"})},
		{name: "missing provider claim", token: mustSignJWT(t, a.jwtSecret, jwt.MapClaims{"id": "user"})},
		{name: "missing id claim", token: mustSignJWT(t, a.jwtSecret, jwt.MapClaims{"provider": "google"})},
		{name: "expired", token: mustSignJWT(t, a.jwtSecret, jwt.MapClaims{
			"provider": "google",
			"id":       "user",
			"exp":      time.Now().Add(-time.Hour).Unix(),
		})},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := a.jwtVerify(tc.token); ok {
				t.Fatal("expected jwtVerify to fail")
			}
		})
	}
}

func TestJWTVerify_rejectsUnexpectedSigningMethod(t *testing.T) {
	a := newFakeAuthn(t, newTestMux())

	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"provider": "google",
		"id":       "user",
	})
	token, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	if _, ok := a.jwtVerify(token); ok {
		t.Fatal("expected jwtVerify to reject none signing method")
	}
}

func mustSignJWT(t *testing.T, secret []byte, claims jwt.MapClaims) string {
	t.Helper()

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}
