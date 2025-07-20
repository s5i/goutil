package authn

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (a *Authn) jwtVerify(token string) (*Token, bool) {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwtSecret, nil
	})
	if err != nil {
		return nil, false
	}

	if claims, ok := t.Claims.(jwt.MapClaims); ok {
		if !t.Valid {
			return nil, false
		}

		provider, ok := claims["provider"].(string)
		if !ok {
			return nil, false
		}
		id, ok := claims["id"].(string)
		if !ok {
			return nil, false
		}

		token := &Token{
			Issuer: provider,
			ID:     id,
		}

		if displayName, ok := claims["display_name"].(string); ok {
			token.DisplayName = displayName
		}

		return token, true
	}
	return nil, false

}

func (a *Authn) jwtBuild(token *Token) (string, time.Time, error) {
	if token == nil {
		return "", time.Time{}, errors.New("token cannot be nil")
	}

	now := time.Now()
	deadline := now.Add(a.jwtTTL)
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"provider":     token.Issuer,
		"id":           token.ID,
		"display_name": token.DisplayName,
		"iat":          now.Unix(),
		"exp":          deadline.Unix(),
	})

	ret, err := t.SignedString(a.jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}
	return ret, deadline, nil
}

func (a *Authn) jwtSetCookie(w http.ResponseWriter, name string, token *Token) error {
	jwt, expires, err := a.jwtBuild(token)
	if err != nil {
		return errors.New("failed to build JWT")
	}

	http.SetCookie(w, &http.Cookie{Name: name, Value: jwt, Path: "/", Expires: expires})
	return nil
}
