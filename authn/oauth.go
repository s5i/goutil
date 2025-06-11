package authn

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
)

func (a *Authn) oAuthDialog(w http.ResponseWriter, r *http.Request) {
	state := randomString(32)

	url := a.oAuthCfg.AuthCodeURL(state)
	a.oAuthInFlight[state] = &oauthState{previousPath: r.URL.Path}

	http.Redirect(w, r, url, http.StatusFound)
}

func (a *Authn) oAuthCallback(w http.ResponseWriter, r *http.Request) {
	states := r.URL.Query()["state"]
	if len(states) != 1 {
		http.Error(w, "need exactly one state in URL params", http.StatusBadRequest)
		return
	}
	state, ok := a.oAuthInFlight[states[0]]
	if !ok {
		http.Error(w, "bad CSRF token", http.StatusUnauthorized)
		return
	}

	codes := r.URL.Query()["code"]
	if len(codes) != 1 {
		http.Error(w, "need exactly one code in URL params", http.StatusBadRequest)
		return
	}

	tok, err := a.oAuthCfg.Exchange(r.Context(), codes[0])
	if err != nil {
		http.Error(w, "failed to exchange code for token", http.StatusBadGateway)
		return
	}

	client := a.oAuthCfg.Client(r.Context(), tok)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v1/userinfo")
	if err != nil {
		http.Error(w, "failed to fetch userinfo", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	var authInfo struct {
		Email    string `json:"email"`
		Verified bool   `json:"verified_email"`
	}
	if err := dec.Decode(&authInfo); err != nil {
		http.Error(w, "failed to decode JSON response", http.StatusBadGateway)
		return
	}
	if !authInfo.Verified {
		http.Error(w, "Google returned verified_email = False", http.StatusUnauthorized)
		return
	}

	if err := a.jwtSetCookie(w, a.jwtCookieName, authInfo.Email); err != nil {
		http.Error(w, "failed to build JWT", http.StatusInternalServerError)
		return
	}

	if state.previousPath != "" {
		http.Redirect(w, r, state.previousPath, http.StatusFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

type oauthState struct {
	previousPath string
}

func randomString(len int) string {
	b := make([]byte, len)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[:len]
}
