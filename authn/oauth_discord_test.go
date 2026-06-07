package authn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ravener/discord-oauth2"
	"golang.org/x/oauth2"
)

func TestDiscordOAuthCallback_validationErrors(t *testing.T) {
	mux := newTestMux()
	a := newDiscordAuthn(t, mux)

	tests := []struct {
		name       string
		url        string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "missing state",
			url:        "/discord?code=abc",
			wantStatus: http.StatusBadRequest,
			wantBody:   "need exactly one state",
		},
		{
			name:       "bad csrf",
			url:        "/discord?state=unknown&code=abc",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "bad CSRF token",
		},
		{
			name:       "missing code",
			url:        "/discord?state=valid",
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

func TestDiscordOAuthCallback_success(t *testing.T) {
	mux := newTestMux()
	a := newDiscordAuthn(t, mux)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			writeOAuthTokenResponse(w)
		case "/users/@me":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id":            "987654321",
				"global_name":   "Display",
				"username":      "user",
				"discriminator": "0",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	a.discordCfg.Endpoint = oauth2.Endpoint{
		AuthURL:  discord.Endpoint.AuthURL,
		TokenURL: api.URL + "/token",
	}

	client := &http.Client{
		Transport: redirectHostTransport(api, map[string]string{
			"discord.com": "/users/@me",
		}),
	}

	seedOAuthState(a, "discord-csrf", "")
	req := httptest.NewRequest(http.MethodGet, "/discord?state=discord-csrf&code=auth-code", nil)
	req = req.WithContext(contextWithHTTPClient(client))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("Location = %q, want /", loc)
	}

	got, ok := a.jwtVerify(rec.Result().Cookies()[0].Value)
	if !ok {
		t.Fatal("cookie JWT invalid")
	}
	if got.Issuer != "discord" || got.ID != "987654321" {
		t.Fatalf("got %+v", got)
	}
	if got.DisplayName != "Display (user)" {
		t.Fatalf("DisplayName = %q", got.DisplayName)
	}
}

func TestDiscordOAuthCallback_legacyDiscriminator(t *testing.T) {
	mux := newTestMux()
	a := newDiscordAuthn(t, mux)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			writeOAuthTokenResponse(w)
		case "/users/@me":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id":            "1",
				"global_name":   "Name",
				"username":      "user",
				"discriminator": "1234",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	a.discordCfg.Endpoint = oauth2.Endpoint{
		AuthURL:  discord.Endpoint.AuthURL,
		TokenURL: api.URL + "/token",
	}

	client := &http.Client{
		Transport: redirectHostTransport(api, map[string]string{
			"discord.com": "/users/@me",
		}),
	}

	seedOAuthState(a, "csrf", "/home")
	req := httptest.NewRequest(http.MethodGet, "/discord?state=csrf&code=auth-code", nil)
	req = req.WithContext(contextWithHTTPClient(client))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "/home" {
		t.Fatalf("Location = %q", rec.Header().Get("Location"))
	}

	got, ok := a.jwtVerify(rec.Result().Cookies()[0].Value)
	if !ok {
		t.Fatal("cookie JWT invalid")
	}
	if got.DisplayName != "Name (user#1234)" {
		t.Fatalf("DisplayName = %q", got.DisplayName)
	}
}
