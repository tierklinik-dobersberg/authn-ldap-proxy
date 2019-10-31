package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func doLogin(ctx context.Context, host, username, password string) (string, string, error) {
	form := url.Values{}

	form.Add("username", username)
	form.Add("password", password)

	req, err := http.NewRequestWithContext(ctx, "POST", host+"/session", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}

	req.Header.Add("Origin", "ldap://app.example.com")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}

	if res.StatusCode == 201 {
		var result struct {
			Result struct {
				Token string `json:"id_token"`
			} `json:"result"`
		}

		if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
			return "", "", err
		}

		var refreshToken string
		for _, cookie := range res.Cookies() {
			if cookie.Name == "authn" {
				refreshToken = cookie.Value
			}
		}

		return result.Result.Token, refreshToken, nil
	}

	return "", "", errors.New(res.Status)
}
