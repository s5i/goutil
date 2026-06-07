package authn

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOAuthDialog_noProviderConfigured(t *testing.T) {
	a := &Authn{
		oAuthInFlight: map[string]*oauthState{},
		jwtSecret:     []byte("secret"),
		jwtTTL:        defaultTestTTL(),
		jwtCookieName: "token",
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	a.oAuthDialog(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "no OAuth provider configured") {
		t.Fatalf("body = %q", body)
	}
}

func TestOAuthDialog_googleRedirect(t *testing.T) {
	mux := newTestMux()
	a := newGoogleAuthn(t, mux)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	a.oAuthDialog(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "accounts.google.com") {
		t.Fatalf("Location = %q, want Google auth URL", loc)
	}

	state := extractOAuthState(t, loc)
	a.oAuthInFlightMu.Lock()
	_, ok := a.oAuthInFlight[state]
	a.oAuthInFlightMu.Unlock()
	if !ok {
		t.Fatal("expected in-flight OAuth state")
	}
}

func TestOAuthDialog_prefersDiscordOverGoogle(t *testing.T) {
	mux := newTestMux()
	a, err := New(
		OptHostname("localhost"),
		OptCallbackBasePath("/"),
		OptGoogleOAuth(&GoogleOAuthConfig{ClientID: "g-id", ClientSecret: "g-secret"}),
		OptDiscordOAuth(&DiscordOAuthConfig{ClientID: "d-id", ClientSecret: "d-secret"}),
		OptMux(mux),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	rec := httptest.NewRecorder()
	a.oAuthDialog(rec, req)

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "discord.com") {
		t.Fatalf("Location = %q, want Discord auth URL", loc)
	}
}

func TestRandomString_length(t *testing.T) {
	for _, length := range []int{8, 16, 32} {
		got := randomString(length)
		if len(got) != length {
			t.Fatalf("randomString(%d) len = %d", length, len(got))
		}
	}
}

func extractOAuthState(t *testing.T, authURL string) string {
	t.Helper()

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing from %q", authURL)
	}
	return state
}

func defaultTestTTL() time.Duration {
	return time.Hour
}
