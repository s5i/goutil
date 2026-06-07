package authn

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNew_requiresHostname(t *testing.T) {
	_, err := New(
		OptFakeOAuth(&FakeOAuthConfig{}),
		OptJWTSecret("secret"),
	)
	if err == nil || !strings.Contains(err.Error(), "hostname cannot be empty") {
		t.Fatalf("expected hostname error, got %v", err)
	}
}

func TestNew_rejectsInvalidJWTOptions(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
		want string
	}{
		{
			name: "negative ttl",
			opts: []Option{
				OptHostname("localhost"),
				OptFakeOAuth(&FakeOAuthConfig{}),
				OptJWTTTL(-time.Second),
			},
			want: "JWT TTL must be greater than zero",
		},
		{
			name: "empty cookie name",
			opts: []Option{
				OptHostname("localhost"),
				OptFakeOAuth(&FakeOAuthConfig{}),
				OptJWTCookieName(""),
			},
			want: "JWT cookie name cannot be empty",
		},
		{
			name: "empty jwt secret",
			opts: []Option{
				OptHostname("localhost"),
				OptFakeOAuth(&FakeOAuthConfig{}),
				OptJWTSecret(""),
			},
			want: "JWT secret cannot be empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.opts...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestNew_rejectsIncompleteOAuthConfigs(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
		want string
	}{
		{
			name: "google missing client id",
			opts: []Option{
				OptHostname("localhost"),
				OptGoogleOAuth(&GoogleOAuthConfig{ClientSecret: "secret"}),
			},
			want: "Google OAuth client ID cannot be empty",
		},
		{
			name: "google missing client secret",
			opts: []Option{
				OptHostname("localhost"),
				OptGoogleOAuth(&GoogleOAuthConfig{ClientID: "id"}),
			},
			want: "Google OAuth client secret cannot be empty",
		},
		{
			name: "discord missing client id",
			opts: []Option{
				OptHostname("localhost"),
				OptDiscordOAuth(&DiscordOAuthConfig{ClientSecret: "secret"}),
			},
			want: "Discord OAuth client ID cannot be empty",
		},
		{
			name: "discord missing client secret",
			opts: []Option{
				OptHostname("localhost"),
				OptDiscordOAuth(&DiscordOAuthConfig{ClientID: "id"}),
			},
			want: "Discord OAuth client secret cannot be empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.opts...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestNew_rejectsMixingFakeAndRealOAuth(t *testing.T) {
	_, err := New(
		OptHostname("localhost"),
		OptCallbackBasePath("/auth"),
		OptMux(newTestMux()),
		OptFakeOAuth(&FakeOAuthConfig{}),
		OptGoogleOAuth(&GoogleOAuthConfig{
			ClientID:     "id",
			ClientSecret: "secret",
		}),
	)
	if err == nil || !strings.Contains(err.Error(), "either real OAuth provider(s) or fake OAuth must be configured") {
		t.Fatalf("expected mixed provider error, got %v", err)
	}
}

func TestNew_rejectsNoOAuthProvider(t *testing.T) {
	_, err := New(OptHostname("localhost"))
	if err == nil || !strings.Contains(err.Error(), "either real OAuth provider(s) or fake OAuth must be configured") {
		t.Fatalf("expected missing provider error, got %v", err)
	}
}

func TestNew_fakeOAuth(t *testing.T) {
	mux := newTestMux()
	a := newFakeAuthn(t, mux)

	if a.fakeCfg == nil {
		t.Fatal("expected fake OAuth config")
	}
	if a.googleCfg != nil || a.discordCfg != nil {
		t.Fatal("expected no real OAuth providers")
	}
	if a.jwtCookieName != "auth-token" {
		t.Fatalf("jwtCookieName = %q, want auth-token", a.jwtCookieName)
	}
}

func TestNew_registersOAuthCallbacks(t *testing.T) {
	t.Run("google", func(t *testing.T) {
		mux := newTestMux()
		a := newGoogleAuthn(t, mux)

		if a.googleCfg == nil {
			t.Fatal("expected google OAuth config")
		}
		if a.googleCfg.RedirectURL != "https://localhost/google" {
			t.Fatalf("RedirectURL = %q", a.googleCfg.RedirectURL)
		}

		req := httptest.NewRequest(http.MethodGet, "/google", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("handler not registered, status = %d", rec.Code)
		}
	})

	t.Run("discord", func(t *testing.T) {
		mux := newTestMux()
		a := newDiscordAuthn(t, mux)

		if a.discordCfg == nil {
			t.Fatal("expected discord OAuth config")
		}
		if a.discordCfg.RedirectURL != "https://localhost/discord" {
			t.Fatalf("RedirectURL = %q", a.discordCfg.RedirectURL)
		}

		req := httptest.NewRequest(http.MethodGet, "/discord", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("handler not registered, status = %d", rec.Code)
		}
	})
}

func TestNew_customCallbackPath(t *testing.T) {
	mux := newTestMux()
	a, err := New(
		OptHostname("example.com"),
		OptCallbackBasePath("/auth/callback"),
		OptGoogleOAuth(&GoogleOAuthConfig{
			ClientID:     "id",
			ClientSecret: "secret",
		}),
		OptMux(mux),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.googleCfg.RedirectURL != "https://example.com/auth/callback/google" {
		t.Fatalf("RedirectURL = %q", a.googleCfg.RedirectURL)
	}
}
