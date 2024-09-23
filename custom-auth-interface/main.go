package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/ory/hydra/sdk/go/hydra/client/admin"
	kratos "github.com/ory/kratos-client-go"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"

	hydraCli "github.com/ory/hydra/sdk/go/hydra/client"
)

// ENV's
var 
(
	PORT, BASE_URL, CLIENT_ID, CLIENT_SECRET, 
	HYDRA_PUBLIC_URL, HYDRA_ADMIN_URL, KRATOS_PUBLIC_URL string
)

// Paths
const (
	signInPath           = "/sign-in"
	signInCallbackPath   = "/callback"
	logoutPath           = "/logout"
	logoutCallbackPath   = "/logout-callback"
	logoutMiddlewarePath = "/logout-middleware"
)

func main() {
	PORT = os.Getenv("PORT")
	if PORT == "" {
		fmt.Println("PORT is not set")
		os.Exit(1)
	}

	BASE_URL = os.Getenv("BASE_URL")
	if BASE_URL == "" {
		fmt.Println("BASE_URL is not set")
		os.Exit(1)
	}

	CLIENT_ID = os.Getenv("CLIENT_ID")
	if CLIENT_ID == "" {
		fmt.Println("CLIENT_ID is not set")
		os.Exit(1)
	}

	CLIENT_SECRET = os.Getenv("CLIENT_SECRET")
	if CLIENT_SECRET == "" {
		fmt.Println("CLIENT_SECRET is not set")
		os.Exit(1)
	}

	HYDRA_PUBLIC_URL = os.Getenv("HYDRA_PUBLIC_URL")
	if HYDRA_PUBLIC_URL == "" {
		HYDRA_PUBLIC_URL = "http://127.0.0.1:4444"
	}

	HYDRA_ADMIN_URL = os.Getenv("HYDRA_ADMIN_URL")
	if HYDRA_ADMIN_URL == "" {
		HYDRA_ADMIN_URL = "http://127.0.0.1:4445"
	}

	KRATOS_PUBLIC_URL = os.Getenv("KRATOS_PUBLIC_URL")
	if KRATOS_PUBLIC_URL == "" {
		KRATOS_PUBLIC_URL = "http://http://127.0.0.1:4433"
	}

	// public page
	http.HandleFunc("/", WelcomeHandler)
	http.HandleFunc("/dashboard", DashboardHandler)

	http.HandleFunc(signInPath, SignInHandler)
	http.HandleFunc(signInCallbackPath, SignInCallbackHandler)

	http.HandleFunc(logoutPath, SignOutHandler)
	http.HandleFunc(logoutCallbackPath, SignOutCallbackHandler)

	http.HandleFunc(logoutMiddlewarePath, LogOutMiddlewareHandler)

	fmt.Println("Server is running on: ", BASE_URL)
	log.Fatal(http.ListenAndServe(":"+PORT, nil))
}

func WelcomeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	oidcCookie, err := GetAuthCookie(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(oidcCookie) > 0 {
		http.Redirect(w, r, BASE_URL+"/dashboard", http.StatusFound)
		return
	}

	tmpl, err := template.ParseFiles("templates/welcome.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := WelcomePageData{
		Title:   "Welcome",
		AuthURL: BASE_URL + signInPath,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	oidcCookie, err := GetAuthCookie(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := DashboardPageData{
		IsLoggedIn: len(oidcCookie) > 0,
	}

	tmpl, err := template.ParseFiles("templates/dashboard.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func SignInHandler(w http.ResponseWriter, r *http.Request) {
	state := uuid.New().String()

	if err := encryptTempToCookie(w, r, "state", state, "/"); err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	nonce := uuid.New().String()

	if err := encryptTempToCookie(w, r, "nonce", nonce, "/"); err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	v := url.Values{
		"client_id":     {CLIENT_ID},
		"redirect_uri":  {BASE_URL + signInCallbackPath},
		"response_type": {"code"},
		"nonce":         {nonce},
		"state":         {state},
		"scope":         {"offline openid"},
	}

	signInURL := HYDRA_PUBLIC_URL + "/oauth2/auth?" + v.Encode()

	http.Redirect(w, r, signInURL, http.StatusFound)
}

func SignInCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	recState := r.URL.Query().Get("state")

	state, err := decryptTempFromCookie(w, r, "state")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "State cookie not found", http.StatusBadRequest)
			return
		}

		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if state != recState {
		http.Error(w, "State does not match", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")

	provider, err := oidc.NewProvider(context.Background(), HYDRA_PUBLIC_URL)
	authConfig := oauth2.Config{
		Endpoint:     provider.Endpoint(),
		ClientID:     CLIENT_ID,
		ClientSecret: CLIENT_SECRET,
		Scopes:       []string{oidc.ScopeOpenID, "profile offline"},
	}

	oauth2Token, err := authConfig.Exchange(
		r.Context(),
		code,
		oauth2.SetAuthURLParam("redirect_uri", fmt.Sprintf("http://%s%s", r.Host, signInCallbackPath)),
	)
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		fmt.Println("No id_token field in oauth2 token.")
		http.Redirect(w, r, BASE_URL, http.StatusFound)
		return
	}

	idToken, err := provider.Verifier(&oidc.Config{ClientID: CLIENT_ID}).Verify(r.Context(), rawIDToken)
	if err != nil {
		fmt.Println("DebugAuth: Failed to verify ID Token: ", err.Error())
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	nonce, err := decryptTempFromCookie(w, r, "nonce")
	if err != nil {
		if err == http.ErrNoCookie {
			fmt.Println("DebugAuth: nonce cookie not found ", err.Error())
			fmt.Println("nonce cookie not found")
			http.Redirect(w, r, BASE_URL, http.StatusFound)
			return
		}

		fmt.Println("DebugAuth: nonce cookie issue", err.Error())
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if idToken.Nonce != nonce {
		http.Error(w, "Invalid ID Token nonce", http.StatusInternalServerError)
		return
	}

	token, err := jwt.ParseSigned(rawIDToken)
	if err != nil {
		fmt.Println("DebugAuth: oauth2Token.AccessToken Issue", err.Error())
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// set session cookie
	claims := jwt.Claims{}
	cmap := make(map[string]interface{})
	_ = token.Claims(nil, &claims, &cmap)

	if err = SetAuthCookie(w, r, &Token{
		IDToken:      rawIDToken,
		AccessToken:  oauth2Token.AccessToken,
		Expiry:       oauth2Token.Expiry,
		RefreshToken: oauth2Token.RefreshToken,
		TokenType:    oauth2Token.TokenType,
	}); err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, BASE_URL+"/dashboard", http.StatusFound)
}

func SignOutHandler(w http.ResponseWriter, r *http.Request) {

	state := uuid.New().String()

	if err := encryptTempToCookie(w, r, "state", state, "/"); err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	v := url.Values{
		"post_logout_redirect_uri": {fmt.Sprintf("http://%s%s", r.Host, logoutCallbackPath)},
		"state":                    {state},
	}

	token, err := AuthCookie(r)
	if err != nil {
		for _, cook := range r.Cookies() {
			cook.MaxAge = -1
			cook.Value = ""
			http.SetCookie(w, cook)
		}
		RemoveAuthCookie(r, w)
		http.Redirect(w, r, BASE_URL, http.StatusFound)
		return
	} else {
		if token.IDToken != "" {
			v.Set("id_token_hint", token.IDToken)
		} else if token.IDToken == "" {
			for _, cook := range r.Cookies() {
				cook.MaxAge = -1
				cook.Value = ""
				http.SetCookie(w, cook)
			}
			RemoveAuthCookie(r, w)
			http.Redirect(w, r, BASE_URL, http.StatusFound)
			return
		}
	}

	var buf bytes.Buffer
	buf.WriteString(HYDRA_PUBLIC_URL + "/oauth2/sessions/logout?")
	buf.WriteString(v.Encode())
	http.Redirect(w, r, buf.String(), http.StatusFound)
}

func SignOutCallbackHandler(w http.ResponseWriter, r *http.Request) {

	recState := r.URL.Query().Get("state")

	state, err := decryptTempFromCookie(w, r, "state")
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if recState != state {
		http.Error(w, "State does not match", http.StatusBadRequest)
		return
	}

	// Initialize the Kratos client
	configuration := kratos.NewConfiguration()

	configuration.HTTPClient = &http.Client{
		Jar: &CookieJar{CookiesList: r.Cookies()},
	}
	configuration.Servers = kratos.ServerConfigurations{
		{URL: KRATOS_PUBLIC_URL}, // Replace with your Kratos public API URL
	}
	client := kratos.NewAPIClient(configuration)

	flow, _, err := client.FrontendAPI.CreateBrowserLogoutFlow(r.Context()).Execute()
	if err != nil {
		log.Printf("Error creating logout flow: %v", err)
		http.Error(w, "Failed to create logout flow", http.StatusInternalServerError)
		return
	}

	RemoveAuthCookie(r, w)

	// Redirect the user to the logout URL
	http.Redirect(w, r, flow.LogoutUrl, http.StatusFound)
}

func LogOutMiddlewareHandler(w http.ResponseWriter, r *http.Request) {

	logoutRequestID := r.URL.Query().Get("logout_challenge")
	if logoutRequestID == "" {
		http.Error(w, "Missing logout challenge", http.StatusBadRequest)
		return
	}

	u, err := url.Parse(HYDRA_ADMIN_URL)
	if err != nil {
		fmt.Printf("Unable to Parse HydraAdimUrl %s", err)
		panic(err)
	}
	clientHydra := hydraCli.NewHTTPClientWithConfig(strfmt.Default, &hydraCli.TransportConfig{
		Host:     u.Host,
		BasePath: u.Path,
		Schemes:  []string{u.Scheme},
	})

	response, err := clientHydra.Admin.AcceptLogoutRequest(&admin.AcceptLogoutRequestParams{
		LogoutChallenge: logoutRequestID,
		Context:         r.Context(),
		HTTPClient:      &http.Client{Timeout: 15 * time.Second},
	})
	if err != nil {
		fmt.Println("The accept logout request endpoint does not respond", err)
		http.Redirect(w, r, BASE_URL, http.StatusFound)
		return
	}

	http.Redirect(w, r, response.Payload.RedirectTo, http.StatusFound)
}
