package authn

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func (a *Authn) discordOAuthCallback(w http.ResponseWriter, r *http.Request) {
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

	tok, err := a.discordCfg.Exchange(r.Context(), codes[0])
	if err != nil {
		http.Error(w, "failed to exchange code for token", http.StatusBadGateway)
		return
	}

	client := a.discordCfg.Client(r.Context(), tok)
	resp, err := client.Get("https://discord.com/api/v10/users/@me")
	if err != nil {
		http.Error(w, "failed to fetch userinfo", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	var user struct {
		ID            string `json:"id"`
		GlobalName    string `json:"global_name"`
		Username      string `json:"username"`
		Discriminator string `json:"discriminator"`
	}
	if err := dec.Decode(&user); err != nil {
		http.Error(w, "failed to decode JSON response", http.StatusBadGateway)
		return
	}

	uName := user.Username
	if user.Discriminator != "0" {
		uName += "#" + user.Discriminator
	}

	if err := a.jwtSetCookie(w, a.jwtCookieName, &Token{
		Issuer:      "discord",
		ID:          user.ID,
		DisplayName: fmt.Sprintf("%s (%s)", user.GlobalName, uName),
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
