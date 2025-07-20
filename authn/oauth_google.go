package authn

import (
	"encoding/json"
	"net/http"
)

func (a *Authn) googleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	states := r.URL.Query()["state"]
	if len(states) != 1 {
		http.Error(w, "need exactly one state in URL params", http.StatusBadRequest)
		return
	}

	stateKey := states[0]
	a.oAuthInFlightMu.Lock()
	state, ok := a.oAuthInFlight[stateKey]
	a.oAuthInFlightMu.Unlock()
	if !ok {
		http.Error(w, "bad CSRF token", http.StatusUnauthorized)
		return
	}

	defer func() {
		a.oAuthInFlightMu.Lock()
		delete(a.oAuthInFlight, stateKey)
		a.oAuthInFlightMu.Unlock()
	}()

	codes := r.URL.Query()["code"]
	if len(codes) != 1 {
		http.Error(w, "need exactly one code in URL params", http.StatusBadRequest)
		return
	}

	tok, err := a.googleCfg.Exchange(r.Context(), codes[0])
	if err != nil {
		http.Error(w, "failed to exchange code for token", http.StatusBadGateway)
		return
	}

	client := a.googleCfg.Client(r.Context(), tok)
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

	if err := a.jwtSetCookie(w, a.jwtCookieName, &Token{
		Issuer:      "google",
		ID:          authInfo.Email,
		DisplayName: authInfo.Email,
	}); err != nil {
		http.Error(w, "failed to build JWT", http.StatusInternalServerError)
		return
	}

	if state.previousPath != "" {
		http.Redirect(w, r, state.previousPath, http.StatusFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}
