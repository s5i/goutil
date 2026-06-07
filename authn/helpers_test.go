package authn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestMux() *http.ServeMux {
	return http.NewServeMux()
}

func newFakeAuthn(t *testing.T, mux *http.ServeMux, opts ...Option) *Authn {
	t.Helper()

	base := []Option{
		OptHostname("localhost"),
		OptFakeOAuth(&FakeOAuthConfig{}),
		OptJWTSecret("test-jwt-secret"),
		OptJWTCookieName("auth-token"),
		OptJWTTTL(time.Hour),
		OptMux(mux),
	}

	a, err := New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func newGoogleAuthn(t *testing.T, mux *http.ServeMux) *Authn {
	t.Helper()

	a, err := New(
		OptHostname("localhost"),
		OptCallbackBasePath("/"),
		OptGoogleOAuth(&GoogleOAuthConfig{
			ClientID:     "google-client-id",
			ClientSecret: "google-client-secret",
		}),
		OptJWTSecret("test-jwt-secret"),
		OptJWTCookieName("auth-token"),
		OptJWTTTL(time.Hour),
		OptMux(mux),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func newDiscordAuthn(t *testing.T, mux *http.ServeMux) *Authn {
	t.Helper()

	a, err := New(
		OptHostname("localhost"),
		OptCallbackBasePath("/"),
		OptDiscordOAuth(&DiscordOAuthConfig{
			ClientID:     "discord-client-id",
			ClientSecret: "discord-client-secret",
		}),
		OptJWTSecret("test-jwt-secret"),
		OptJWTCookieName("auth-token"),
		OptJWTTTL(time.Hour),
		OptMux(mux),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func seedOAuthState(a *Authn, stateKey, previousPath string) {
	a.oAuthInFlightMu.Lock()
	a.oAuthInFlight[stateKey] = &oauthState{previousPath: previousPath}
	a.oAuthInFlightMu.Unlock()
}

func contextWithHTTPClient(client *http.Client) context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, client)
}

func redirectHostTransport(target *httptest.Server, hosts map[string]string) http.RoundTripper {
	targetURL, _ := url.Parse(target.URL)
	inner := target.Client().Transport
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if path, ok := hosts[req.URL.Host]; ok {
			clone := req.Clone(req.Context())
			u := *targetURL
			u.Path = path
			clone.URL = &u
			return inner.RoundTrip(clone)
		}
		return http.DefaultTransport.RoundTrip(req)
	})
}

func writeOAuthTokenResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	fmt.Fprint(w, "access_token=access-token&token_type=Bearer&expires_in=3600")
}

func recordResponse(handler http.Handler) (*httptest.ResponseRecorder, *http.Request) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, req
}
