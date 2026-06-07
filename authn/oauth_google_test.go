package authn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func TestGoogleOAuthCallback_validationErrors(t *testing.T) {
	mux := newTestMux()
	a := newGoogleAuthn(t, mux)

	tests := []struct {
		name       string
		url        string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "missing state",
			url:        "/google?code=abc",
			wantStatus: http.StatusBadRequest,
			wantBody:   "need exactly one state",
		},
		{
			name:       "duplicate state",
			url:        "/google?state=a&state=b&code=abc",
			wantStatus: http.StatusBadRequest,
			wantBody:   "need exactly one state",
		},
		{
			name:       "bad csrf",
			url:        "/google?state=unknown&code=abc",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "bad CSRF token",
		},
		{
			name:       "missing code",
			url:        "/google?state=valid",
			wantStatus: http.StatusBadRequest,
			wantBody:   "need exactly one code",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(tc.url, "state=valid") {
				seedOAuthState(a, "valid", "")
			}

			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("body = %q, want substring %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}

func TestGoogleOAuthCallback_success(t *testing.T) {
	mux := newTestMux()
	a := newGoogleAuthn(t, mux)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			writeOAuthTokenResponse(w)
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"email":          "user@example.com",
				"verified_email": true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	a.googleCfg.Endpoint = oauth2.Endpoint{
		AuthURL:  google.Endpoint.AuthURL,
		TokenURL: api.URL + "/token",
	}

	client := &http.Client{
		Transport: redirectHostTransport(api, map[string]string{
			"www.googleapis.com": "/userinfo",
		}),
	}

	seedOAuthState(a, "csrf-state", "/welcome")
	req := httptest.NewRequest(http.MethodGet, "/google?state=csrf-state&code=auth-code", nil)
	req = req.WithContext(contextWithHTTPClient(client))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/welcome" {
		t.Fatalf("Location = %q, want /welcome", loc)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != a.jwtCookieName {
		t.Fatalf("unexpected cookies: %+v", cookies)
	}

	got, ok := a.jwtVerify(cookies[0].Value)
	if !ok {
		t.Fatal("cookie JWT invalid")
	}
	if got.Issuer != "google" || got.ID != "user@example.com" {
		t.Fatalf("got %+v", got)
	}

	a.oAuthInFlightMu.Lock()
	_, stillPresent := a.oAuthInFlight["csrf-state"]
	a.oAuthInFlightMu.Unlock()
	if stillPresent {
		t.Fatal("expected OAuth state to be cleared")
	}
}

func TestGoogleOAuthCallback_rejectsUnverifiedEmail(t *testing.T) {
	mux := newTestMux()
	a := newGoogleAuthn(t, mux)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			writeOAuthTokenResponse(w)
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"email":          "user@example.com",
				"verified_email": false,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	a.googleCfg.Endpoint = oauth2.Endpoint{
		AuthURL:  google.Endpoint.AuthURL,
		TokenURL: api.URL + "/token",
	}

	client := &http.Client{
		Transport: redirectHostTransport(api, map[string]string{
			"www.googleapis.com": "/userinfo",
		}),
	}

	seedOAuthState(a, "csrf", "")
	req := httptest.NewRequest(http.MethodGet, "/google?state=csrf&code=auth-code", nil)
	req = req.WithContext(contextWithHTTPClient(client))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "verified_email = False") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}
