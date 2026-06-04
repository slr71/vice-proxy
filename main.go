package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	stderrors "errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cyverse-de/go-mod/viceauth"
	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
)

// errAccessDenied is the sentinel returned by authenticateAndAuthorize when a
// user is neither in the per-analysis allowed-users list nor flagged as an
// admin in their session. Callers should compare with errors.Is rather than
// matching error strings.
var errAccessDenied = stderrors.New("access denied")

var log = logrus.WithFields(logrus.Fields{
	"service": "vice-proxy",
	"art-id":  "vice-proxy",
	"group":   "org.cyverse",
})

const (
	stateSessionName = "state-session"
	stateSessionKey  = "state-session-key"
	sessionName      = "proxy-session"
	sessionKey       = "proxy-session-key"
	keycloakSidKey   = "keycloak-sid"
	adminFlagKey     = "is-admin" // session value flagging entitlement-bearing admins

	// permissionsFilePath is the path to the ConfigMap-mounted allowed-users file.
	permissionsFilePath = "/etc/vice-permissions/allowed-users"
)

// VICEProxy contains the application logic that handles Keycloak OIDC
// authentication, session management, ConfigMap-based authorization, and
// request proxying.
type VICEProxy struct {
	keycloakBaseURL      string                // The URL to use when checking for Keycloak authentication.
	keycloakRealm        string                // The realm to use when checking for Keycloak authentication.
	keycloakClientID     string                // The OIDC client ID for Keycloak.
	keycloakClientSecret string                // The OIDC client secret for Keycloak.
	frontendURL          string                // The app's public base URL; used to build the post-login browser redirect, not the OAuth redirect_uri (see operatorCallbackURL).
	backendURL           string                // The backend URL to forward to.
	wsbackendURL         string                // The websocket URL to forward requests to.
	resourceName         string                // The UUID of the analysis.
	sessionStore         *sessions.CookieStore // The backend session storage.
	ssoClient            http.Client           // The HTTP client for token exchange and JWKS requests to the IDP.
	disableAuth          bool                  // If true, authentication and authorization are disabled.
	jwksAutoRefresh      *jwk.AutoRefresh      // Cached JWKS fetcher, nil if caching is disabled.
	jwksCertsURL         string                // The resolved JWKS certs URL, set during initialization.
	activeSessions       sync.Map              // Tracks valid Keycloak session IDs; entries removed on logout.
	allowedUsers         sync.Map              // In-memory set of usernames allowed to access this analysis.
	adminEntitlements    []string              // Entitlement-claim values that grant admin access regardless of allowedUsers.
	operatorCallbackURL  string                // Static redirect_uri registered in Keycloak; the vice-operator relays the auth code from here back to this app.
	stateCodec           *viceauth.Codec       // Signs and verifies the OAuth state parameter that round-trips through the operator relay.
}

// loadAllowedUsers reads the allowed-users file and populates the in-memory set.
// Returns the number of users loaded, or an error if the file cannot be read.
func (c *VICEProxy) loadAllowedUsers(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening permissions file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// Read all users from the file before touching the live map.
	newUsers := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			newUsers[line] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("reading permissions file %s: %w", path, err)
	}

	// Swap in the new set: clear old entries, then store new ones.
	// Note: there is a brief window between the Range+Delete and Store passes
	// during which the map is empty. This is acceptable because the worst case
	// is a single request getting a spurious 403 while the reload races; the
	// file-watch goroutine is the only writer so the window is very short.
	c.allowedUsers.Range(func(key, _ any) bool {
		c.allowedUsers.Delete(key)
		return true
	})
	for user := range newUsers {
		c.allowedUsers.Store(user, true)
	}

	return len(newUsers), nil
}

// isUserAllowed checks whether a username is in the allowed-users set.
// The allowed-users file may contain full usernames with a domain suffix
// (e.g. "user@iplantcollaborative.org") while the Keycloak JWT preferred_username
// is typically the bare username (e.g. "user"). This method checks both forms:
// the exact username, and each entry with the @domain portion stripped.
func (c *VICEProxy) isUserAllowed(username string) bool {
	// Direct match (handles both bare-to-bare and full-to-full).
	if _, ok := c.allowedUsers.Load(username); ok {
		return true
	}

	// Check if any entry matches after stripping the @domain suffix.
	found := false
	c.allowedUsers.Range(func(key, _ any) bool {
		entry, _ := key.(string)
		if bare, _, hasSuffix := strings.Cut(entry, "@"); hasSuffix && bare == username {
			found = true
			return false // stop iteration
		}
		return true
	})
	return found
}

// watchPermissionsFile watches the permissions directory for ConfigMap volume
// updates (K8s performs a symlink swap) and reloads the allowed-users set.
// Returns an error if the watcher cannot be created; the caller should treat
// this as fatal since the proxy will never pick up permission changes.
func (c *VICEProxy) watchPermissionsFile(path string) error {
	dir := filepath.Dir(path)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating fsnotify watcher for %s: %w", dir, err)
	}

	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return fmt.Errorf("adding watch on %s: %w", dir, err)
	}

	log.Infof("watching %s for permission updates", dir)

	go func() {
		defer func() { _ = watcher.Close() }()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// K8s ConfigMap volumes update via symlink swap, which
				// generates Create events on the ..data symlink.
				if event.Op&(fsnotify.Create|fsnotify.Write) != 0 {
					count, err := c.loadAllowedUsers(path)
					if err != nil {
						log.Errorf("failed to reload permissions: %v", err)
					} else {
						log.Infof("reloaded permissions: %d allowed users", count)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Errorf("fsnotify error: %v", err)
			}
		}
	}()

	return nil
}

// KeycloakURL generates a URL for a Keycloak OpenID Connect endpoint. Optional
// path components are appended after the base OpenID Connect path.
func (c *VICEProxy) KeycloakURL(components ...string) (*url.URL, error) {
	keycloakURL, err := url.Parse(c.keycloakBaseURL)
	if err != nil {
		return nil, err
	}

	// Build the fixed OpenID Connect path prefix, then append any caller-supplied
	// components. JoinPath handles percent-encoding and slash normalization.
	parts := append([]string{"realms", c.keycloakRealm, "protocol", "openid-connect"}, components...)
	return keycloakURL.JoinPath(parts...), nil
}

// TokenResponse represents the response to an OpenID Connect token endpoint.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

// FetchKeycloakCerts calls Keycloak's certificate endpoint to get the set of signing certificates, and returns
// the parsed certificate set. If JWKS caching is enabled, returns the cached key set.
func (c *VICEProxy) FetchKeycloakCerts() (jwk.Set, error) {
	if c.jwksAutoRefresh != nil {
		return c.jwksAutoRefresh.Fetch(context.Background(), c.jwksCertsURL)
	}

	url, err := c.KeycloakURL("certs")
	if err != nil {
		return nil, err
	}

	resp, err := c.ssoClient.Get(url.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return jwk.Parse(body)
}

// ValidateKeycloakToken verifies the signature of a Keycloak token and returns a parsed version of it.
func (c *VICEProxy) ValidateKeycloakToken(encodedToken string) (jwt.Token, error) {
	keySet, err := c.FetchKeycloakCerts()
	if err != nil {
		return nil, err
	}

	return jwt.Parse([]byte(encodedToken), jwt.WithKeySet(keySet))
}

// extractStringClaim returns the value of a JWT claim as a string, or ""
// if the claim is missing, not a string, or empty.
func extractStringClaim(token jwt.Token, claim string) string {
	raw, ok := token.Get(claim)
	if !ok {
		return ""
	}
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	return s
}

// extractStringSliceClaim returns the value of a JWT claim that is expected
// to be an array of strings. Returns nil if the claim is missing or the
// underlying value is not a string-array. The Keycloak JSON decoder may
// surface the values as []any (each element a string) or []string
// depending on the path, so both shapes are handled.
func extractStringSliceClaim(token jwt.Token, claim string) []string {
	raw, ok := token.Get(claim)
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// parseAdminEntitlements splits a comma-separated entitlement list, trims
// whitespace, and drops empty entries.
func parseAdminEntitlements(raw string) []string {
	var out []string
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// computeIsAdmin reports whether a token's entitlement claim grants admin
// access — i.e., any of its values match the configured adminEntitlements
// allowlist. Captured at OAuth-callback time and persisted in the session
// so subsequent requests don't have to re-parse the JWT.
func (c *VICEProxy) computeIsAdmin(token jwt.Token) bool {
	return anyMatch(extractStringSliceClaim(token, "entitlement"), c.adminEntitlements)
}

// anyMatch reports whether any element of a is also present in b. Both
// inputs are typically very small (≤10 entries each) so a linear scan is
// adequate and avoids the allocation of a set.
func anyMatch(a, b []string) bool {
	for _, v := range a {
		if slices.Contains(b, v) {
			return true
		}
	}
	return false
}

// HandleAuthorizationCode accepts an authorization code in the query string and uses it to obtain an access token.
func (c *VICEProxy) HandleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	log.Debug("validating an authorization code received from Keycloak")
	var err error

	// Surface a Keycloak-side error (e.g. the user denied consent) directly.
	// Such a response carries no code or state, so without this check the flow
	// would fall through to the state check and report a confusing "no state
	// found". Only the bounded RFC 6749 error code is echoed to the browser;
	// the full description is logged server-side.
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		log.Errorf("Keycloak returned an error: %s: %s", errParam, r.URL.Query().Get("error_description"))
		http.Error(w, fmt.Sprintf("authentication failed: %s", errParam), http.StatusUnauthorized)
		return
	}

	// Validate the state query parameter to mitigate CSRF attacks. The state is
	// an HMAC-signed blob produced by RequireKeycloakAuth and relayed back
	// untouched by the vice-operator. Only its StateID is checked against the
	// cookie here; the Origin field is the operator's concern.
	rawState := r.URL.Query().Get("state")
	if rawState == "" {
		err = errors.New("no state found in query string")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	stateClaims, err := c.stateCodec.Decode(rawState)
	if err != nil {
		err = errors.Wrap(err, "failed to decode the OAuth state")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, err := c.sessionStore.Get(r, stateSessionName)
	if err != nil {
		err = errors.New("unable to get the state session")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	expectedState, ok := session.Values[stateSessionKey]
	if !ok {
		err = errors.New("no state ID found in state session")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if expectedState != stateClaims.StateID {
		err = errors.New("expected state ID does not equal actual state ID")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Extract the authorization code from the request URL.
	code := r.URL.Query().Get("code")
	if code == "" {
		err = errors.New("authorization code not found in query string")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Build the token URL.
	tokenURL, err := c.KeycloakURL("token")
	if err != nil {
		err = errors.Wrap(err, "failed to create the Keycloak token URL")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Build the clean post-login redirect URL — where the browser is sent once
	// the token is obtained. The browser is already back on this app's domain
	// at this point, so it is derived from frontendURL plus the original path,
	// with the OAuth round-trip parameters stripped.
	redirectURL, err := url.Parse(c.frontendURL)
	if err != nil {
		err = errors.Wrap(err, "failed to parse the frontend URL")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	params := r.URL.Query()
	params.Del("code")
	params.Del("session_state")
	params.Del("state")
	params.Del("iss") // Keycloak 24+ adds issuer to callback URL
	redirectURL.RawQuery = params.Encode()
	redirectURL.Path = r.URL.Path

	// Build the form parameters. The redirect_uri here must byte-match the one
	// sent to Keycloak's auth endpoint (the operator callback URL), not this
	// app's URL — OAuth requires the two to be identical.
	formParams := url.Values{}
	formParams.Set("grant_type", "authorization_code")
	formParams.Set("code", code)
	formParams.Set("redirect_uri", c.operatorCallbackURL)
	formParams.Set("client_id", c.keycloakClientID)
	formParams.Set("client_secret", c.keycloakClientSecret)

	// Attempt to get the token.
	log.Debug("attempting to exchange the authorization code for a token")
	resp, err := c.ssoClient.PostForm(tokenURL.String(), formParams)
	if err != nil {
		err = errors.Wrap(err, "failed to get the token from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Extract the token from the response.
	log.Debug("reading the response from Keycloak")
	body, err := io.ReadAll(resp.Body)
	log.Debug("finished reading the response from Keycloak")
	if err != nil {
		err = errors.Wrap(err, "failed to read the response from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the response body.
	tokenResponse := &TokenResponse{}
	err = json.Unmarshal(body, tokenResponse)
	if err != nil {
		err = errors.Wrap(err, "failed to parse the response from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tokenResponse.AccessToken == "" {
		err = errors.New("no access token found in response from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Validate the token.
	token, err := c.ValidateKeycloakToken(tokenResponse.AccessToken)
	if err != nil {
		err = errors.Wrap(err, "failed to validate token from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get the username from the token.
	username, ok := token.Get("preferred_username")
	if !ok {
		err = errors.New("no username found in the token from Keycloak")
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract and validate the username string from the token claim.
	usernameStr, ok := username.(string)
	if !ok || usernameStr == "" {
		err = fmt.Errorf("preferred_username claim has unexpected type %T or is empty", username)
		log.Error(err)
		http.Error(w, "invalid token: username claim is not a string", http.StatusInternalServerError)
		return
	}

	// Determine admin status from the JWT's entitlement claim. Admins bypass
	// the per-analysis allowed-users list — they can access any running
	// analysis. Captured at login and stored in the session so subsequent
	// requests don't need to re-parse the JWT.
	isAdmin := c.computeIsAdmin(token)

	// Check ConfigMap-based authorization: the user must be in the allowed-users
	// list, or be an admin (entitlement-bearer).
	if !c.isUserAllowed(usernameStr) && !isAdmin {
		log.Errorf("user %s not in allowed-users list and not an admin for analysis %s", usernameStr, c.resourceName)
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	// Store the username and Keycloak session ID in the session.
	var s *sessions.Session
	s, err = c.sessionStore.Get(r, sessionName)
	if err != nil {
		log.Warnf("failed to get session store, creating new session: %v", err)
	}
	s.Values[sessionKey] = usernameStr
	s.Values[adminFlagKey] = isAdmin

	// Extract and store the Keycloak session ID for session tracking.
	// Try the standard "sid" claim first, then fall back to "session_state" which
	// Keycloak includes in access tokens by default even when "sid" is not mapped.
	sidStr := extractStringClaim(token, "sid")
	if sidStr == "" {
		sidStr = extractStringClaim(token, "session_state")
	}
	if sidStr != "" {
		s.Values[keycloakSidKey] = sidStr
		c.activeSessions.Store(sidStr, usernameStr)
		log.Debugf("registered active session: sid=%s user=%s", sidStr, usernameStr)
	} else {
		log.Warn("no sid or session_state claim in token; session will not be tracked for logout")
	}

	if err = s.Save(r, w); err != nil {
		log.Errorf("failed to save session: %v", err)
		http.Error(w, "failed to save session", http.StatusInternalServerError)
		return
	}

	// Redirect the user to the redirect URL, which was determined above.
	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
}

// RequireKeycloakAuth ensures that the user is logged in via Keycloak.
func (c *VICEProxy) RequireKeycloakAuth(w http.ResponseWriter, r *http.Request) {
	log.Debug("redirecting user to Keycloak for authentication")

	// Generate a UUID for a state ID so that we can validate it later.
	stateID, err := uuid.NewUUID()
	if err != nil {
		err = errors.Wrap(err, "failed to generate the state ID")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session, _ := c.sessionStore.Get(r, stateSessionName)
	session.Values[stateSessionKey] = stateID.String()
	err = session.Save(r, w)
	if err != nil {
		err = errors.Wrap(err, "failed to save the state ID in the session")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Build the origin URL: the app URL the browser should be returned to once
	// the vice-operator relays the authorization code back. It travels (signed)
	// in the state parameter rather than as redirect_uri, because Keycloak
	// cannot wildcard-match per-app VICE subdomains — only the operator's fixed
	// callback URL is registered as a valid redirect_uri.
	originURL, err := url.Parse(c.frontendURL)
	if err != nil {
		err = errors.Wrapf(err, "failed to parse the frontend URL: %s", c.frontendURL)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	originURL.Path = r.URL.Path
	originURL.RawQuery = r.URL.RawQuery

	state, err := c.stateCodec.Encode(viceauth.StateClaims{
		StateID: stateID.String(),
		Origin:  originURL.String(),
	})
	if err != nil {
		err = errors.Wrap(err, "failed to encode the OAuth state")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Build the login URL and set the query parameters.
	loginURL, err := c.KeycloakURL("auth")
	if err != nil {
		err = errors.Wrap(err, "failed to build the Keycloak authorization URL")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	params := loginURL.Query()
	params.Set("client_id", c.keycloakClientID)
	params.Set("state", state)
	params.Set("redirect_uri", c.operatorCallbackURL)
	params.Set("scope", "openid")
	params.Set("response_type", "code")
	loginURL.RawQuery = params.Encode()

	// Redirect the user to the login URL.
	http.Redirect(w, r, loginURL.String(), http.StatusTemporaryRedirect)
}

// ResetSessionExpiration should reset the session expiration time.
func (c *VICEProxy) ResetSessionExpiration(w http.ResponseWriter, r *http.Request) error {
	session, err := c.sessionStore.Get(r, sessionName)
	if err != nil {
		return err
	}

	msg, ok := session.Values[sessionKey]
	if !ok {
		return errors.New("session value not found")
	}

	str, ok := msg.(string)
	if !ok {
		return errors.New("session value is not a string")
	}

	session.Values[sessionKey] = str
	return session.Save(r, w)
}

// ActiveSession describes a single active user session.
type ActiveSession struct {
	SessionID string `json:"session_id"`
	Username  string `json:"username"`
}

// ActiveSessionsResponse is returned by GET /active-sessions.
type ActiveSessionsResponse struct {
	Sessions []ActiveSession `json:"sessions"`
}

// HandleActiveSessions returns the list of currently active user sessions.
// Called by the operator (not browser users), so it is registered without auth.
func (c *VICEProxy) HandleActiveSessions(w http.ResponseWriter, r *http.Request) {
	var sessions []ActiveSession
	c.activeSessions.Range(func(key, value any) bool {
		sid, _ := key.(string)
		username, _ := value.(string)
		sessions = append(sessions, ActiveSession{
			SessionID: sid,
			Username:  username,
		})
		return true
	})

	resp := ActiveSessionsResponse{Sessions: sessions}
	body, err := json.Marshal(resp)
	if err != nil {
		log.Errorf("failed to marshal active sessions response: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// LogoutUserRequest is the request body for POST /logout-user.
type LogoutUserRequest struct {
	Username string `json:"username"`
}

// LogoutUserResponse is returned by POST /logout-user.
type LogoutUserResponse struct {
	SessionsInvalidated int `json:"sessions_invalidated"`
}

// HandleLogoutUser invalidates all active sessions for a given username.
// Called by the operator (not browser users), so it is registered without auth.
func (c *VICEProxy) HandleLogoutUser(w http.ResponseWriter, r *http.Request) {
	var req LogoutUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Errorf("failed to decode logout-user request: %v", err)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	// Delete all sessions for this user. sync.Map.Delete inside Range is safe
	// per the Go documentation, matching the pattern in loadAllowedUsers.
	var count int
	c.activeSessions.Range(func(key, value any) bool {
		if username, _ := value.(string); username == req.Username {
			c.activeSessions.Delete(key)
			log.Infof("invalidated session %s for user %s via logout-user", key, req.Username)
			count++
		}
		return true
	})

	resp := LogoutUserResponse{SessionsInvalidated: count}
	body, err := json.Marshal(resp)
	if err != nil {
		log.Errorf("failed to marshal logout-user response: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// Session implements the mux.Matcher interface so that requests can be routed
// based on cookie existence. Returns true if authentication is required.
func (c *VICEProxy) Session(r *http.Request, m *mux.RouteMatch) bool {
	session, err := c.sessionStore.Get(r, sessionName)
	if err != nil {
		return true
	}

	msgraw, ok := session.Values[sessionKey]
	if !ok {
		return true
	}
	msg, ok := msgraw.(string)
	if !ok || msg == "" {
		log.Debug("session value was empty or not a string")
		return true
	}

	// Check if session was invalidated via logout
	if sidRaw, ok := session.Values[keycloakSidKey]; ok {
		sid, ok := sidRaw.(string)
		if !ok || sid == "" {
			log.Debug("session has invalid keycloak sid")
			return true
		}
		if _, valid := c.activeSessions.Load(sid); !valid {
			log.Debugf("session %s was invalidated via logout", sid)
			return true
		}
	}

	return false
}

// ReverseProxy returns a proxy that forwards requests to the configured
// backend URL. It can act as a http.Handler and properly handles WebSocket upgrades.
func (c *VICEProxy) ReverseProxy() (*httputil.ReverseProxy, error) {
	backend, err := url.Parse(c.backendURL)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse %s", c.backendURL)
	}

	proxy := httputil.NewSingleHostReverseProxy(backend)

	// Customize the director to handle WebSocket upgrade properly
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// For WebSocket requests, ensure proper scheme in target URL
		if c.isWebsocket(req) {
			// The backend URL stays http:// but the proxy will handle upgrade
			log.Infof("WebSocket upgrade request detected for %s", req.URL.Path)
		}
	}

	return proxy, nil
}

// isWebsocket returns true if the request is a WebSocket upgrade request. Adapted
// from https://groups.google.com/d/msg/golang-nuts/KBx9pDlvFOc/0tR1gBRfFVMJ.
func (c *VICEProxy) isWebsocket(r *http.Request) bool {
	connection := r.Header.Get("Connection")
	if !strings.Contains(strings.ToLower(connection), "upgrade") {
		return false
	}
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// readinessClient deliberately does not follow redirects so that a backend
// answering with a 3xx (e.g. RStudio's unsupported-browser redirect for the
// non-browser User-Agent used here) counts as "up", matching kubelet's HTTP
// probe semantics. Following the redirect chases an external URL that 404s and
// would wrongly report a healthy backend as down, leaving the pod stuck at 1/2.
var readinessClient = &http.Client{
	Timeout: 5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// backendIsReady returns true when the backend responds with a 2xx or 3xx status.
// Uses a context-free poll because this is a health-check with no ambient request
// context; readinessClient.Timeout bounds it.
//
//nolint:noctx // no request context available in health-check polling
func (c *VICEProxy) backendIsReady(backendURL string) (bool, error) {
	resp, err := readinessClient.Get(backendURL) //nolint:noctx
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body) // drain so the connection can be reused

	return resp.StatusCode >= 200 && resp.StatusCode < 400, nil
}

// URLIsReady will write out a JSON-encoded response in the format
// {"ready":boolean}, telling whether or not the underlying application is ready
// for business yet.
func (c *VICEProxy) URLIsReady(w http.ResponseWriter, r *http.Request) {
	log.Infof("checking backend readiness at %s", c.backendURL)
	ready, err := c.backendIsReady(c.backendURL)
	if err != nil {
		log.Errorf("backend readiness check failed: %v", err)
	}

	log.Infof("backend ready status: %v", ready)

	data := map[string]bool{
		"ready": ready,
	}

	body, err := json.Marshal(data)
	if err != nil {
		log.Errorf("failed to marshal readiness response: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ready {
		_, _ = w.Write(body)
	} else {
		http.Error(w, string(body), http.StatusNotAcceptable)
	}
}

// FrontendURL returns the configured frontend URL as JSON. Called by
// app-exposer via the in-cluster Service to discover the access URL.
func (c *VICEProxy) FrontendURL(w http.ResponseWriter, r *http.Request) {
	body, err := json.Marshal(map[string]string{"url": c.frontendURL})
	if err != nil {
		log.Errorf("failed to encode frontend URL response: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// GetFrontendHost returns the host and port portions of the resource name.
func (c *VICEProxy) GetFrontendHost() (string, error) {
	svcURL, err := url.Parse(c.frontendURL)
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse the frontend URL %s", c.frontendURL)
	}

	return svcURL.Host, nil
}

// authenticateAndAuthorize validates the user's session and checks if they have permission
// to access the resource via the ConfigMap-based allowed-users list.
// Returns the username on success, or an error on failure.
func (c *VICEProxy) authenticateAndAuthorize(w http.ResponseWriter, r *http.Request) (string, error) {
	// Get the username from the cookie
	session, err := c.sessionStore.Get(r, sessionName)
	if err != nil {
		return "", errors.Wrap(err, "failed to get session")
	}

	// Check if the session contains a username
	usernameValue, ok := session.Values[sessionKey]
	if !ok || usernameValue == nil {
		return "", errors.New("no session found")
	}

	username, ok := usernameValue.(string)
	if !ok || username == "" {
		return "", errors.New("username was empty or invalid")
	}
	log.Infof("authenticated user: %s", username)

	// Check if session was invalidated via logout.
	// This mirrors the check in Session() (the mux.Matcher) as defense-in-depth:
	// Session() guards the route match, but authenticateAndAuthorize guards the
	// proxied request itself, which may arrive via a route that bypasses Session().
	if sidRaw, ok := session.Values[keycloakSidKey]; ok {
		sid, ok := sidRaw.(string)
		if !ok || sid == "" {
			return "", errors.New("invalid session ID in cookie")
		}
		if _, valid := c.activeSessions.Load(sid); !valid {
			log.Infof("session %s was invalidated via logout", sid)
			return "", errors.New("session invalidated")
		}
	}

	// Read admin flag captured at login. Default false (untyped/missing).
	isAdmin, _ := session.Values[adminFlagKey].(bool)

	// Check ConfigMap-based authorization: the user must be in the allowed-users
	// list, or be an admin (entitlement-bearer captured at login). Wrap the
	// sentinel so callers can detect access denial with errors.Is without
	// string-matching the message.
	if !c.isUserAllowed(username) && !isAdmin {
		return "", fmt.Errorf("user %s: %w", username, errAccessDenied)
	}

	// CRITICAL: Don't reset session for WebSocket upgrades (would corrupt the upgrade handshake)
	if !c.isWebsocket(r) {
		if err = c.ResetSessionExpiration(w, r); err != nil {
			return "", errors.Wrap(err, "error resetting session expiration")
		}
	}

	return username, nil
}

// Proxy returns a handler that can support both websockets and http requests.
func (c *VICEProxy) Proxy() (http.Handler, error) {
	rp, err := c.ReverseProxy()
	if err != nil {
		return nil, err
	}

	frontendHost, err := c.GetFrontendHost()
	if err != nil {
		return nil, err
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Infof("handling request for %s from remote address %s", r.URL.String(), r.RemoteAddr)

		// Conditionally perform authentication and authorization
		if !c.disableAuth {
			username, err := c.authenticateAndAuthorize(w, r)
			if err != nil {
				log.Errorf("auth/authz error: %v", err)
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			log.Debugf("request authorized for user: %s", username)
		} else {
			log.Debug("authentication disabled, allowing unauthenticated access")
		}

		// Override the X-Forwarded-Host header.
		r.Header.Set("X-Forwarded-Host", frontendHost)

		// The reverse proxy handles both HTTP and WebSocket upgrade requests transparently
		log.Infof("proxying request to %s%s", c.backendURL, r.URL.Path)
		rp.ServeHTTP(w, r)
	}), nil
}

type originFlags []string

func (o *originFlags) String() string {
	return strings.Join([]string(*o), ",")
}

func (o *originFlags) Set(s string) error {
	parts := strings.Split(s, ",")
	*o = append(*o, parts...)
	return nil
}

func main() {
	logrus.SetReportCaller(true)
	logrus.SetLevel(logrus.InfoLevel)

	// Per-pod flags — injected by the vice-operator transform.
	var (
		backendURL          = flag.String("backend-url", "http://localhost:60000", "The hostname and port to proxy requests to.")
		wsbackendURL        = flag.String("ws-backend-url", "", "The backend URL for the handling websocket requests. Defaults to the value of --backend-url with a scheme of ws://")
		listenAddr          = flag.String("listen-addr", "0.0.0.0:8080", "The listen port number.")
		analysisID          = flag.String("analysis-id", "", "The UUID of the analysis to use for authorization.")
		maxAge              = flag.Int("max-age", 0, "The idle timeout for session, in seconds.")
		sslCert             = flag.String("ssl-cert", "", "Path to the SSL .crt file.")
		sslKey              = flag.String("ssl-key", "", "Path to the SSL .key file.")
		encodedSSOTimeout   = flag.String("sso-timeout", "5s", "The timeout period for back-channel requests to the identity provider.")
		encodedReadTimeout  = flag.String("read-timeout", "48h", "The maximum duration for reading the entire request, including the body.")
		encodedWriteTimeout = flag.String("write-timeout", "48h", "The maximum duration before timing out writes of the response.")
		encodedIdleTimeout  = flag.String("idle-timeout", "5000s", "The maximum amount of time to wait for the next request when keep-alives are enabled.")
		encodedJWKSCacheTTL = flag.String("jwks-cache-ttl", "1h", "How long to cache Keycloak JWKS certificates. Set to 0 to disable caching.")
	)

	flag.Parse()

	// Cluster-specific config from env vars (via cluster-config-secret).
	keycloakBaseURL := os.Getenv("KEYCLOAK_BASE_URL")
	keycloakRealm := os.Getenv("KEYCLOAK_REALM")
	keycloakClientID := os.Getenv("KEYCLOAK_CLIENT_ID")
	keycloakClientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")
	disableAuth := strings.EqualFold(os.Getenv("DISABLE_AUTH"), "true")
	adminEntitlements := parseAdminEntitlements(os.Getenv("ADMIN_ENTITLEMENTS"))

	// operatorCallbackURL is the single static redirect_uri registered in
	// Keycloak for the vice-users client; stateHMACSecret signs the OAuth state
	// blob so the vice-operator relay can trust the embedded app URL.
	operatorCallbackURL := os.Getenv("OPERATOR_CALLBACK_URL")
	stateHMACSecret := os.Getenv("STATE_HMAC_SECRET")

	// Validate required Keycloak env vars when auth is enabled to fail fast
	// rather than producing confusing URL construction errors at login time.
	if !disableAuth {
		var missing []string
		if keycloakBaseURL == "" {
			missing = append(missing, "KEYCLOAK_BASE_URL")
		}
		if keycloakRealm == "" {
			missing = append(missing, "KEYCLOAK_REALM")
		}
		if keycloakClientID == "" {
			missing = append(missing, "KEYCLOAK_CLIENT_ID")
		}
		if keycloakClientSecret == "" {
			missing = append(missing, "KEYCLOAK_CLIENT_SECRET")
		}
		if operatorCallbackURL == "" {
			missing = append(missing, "OPERATOR_CALLBACK_URL")
		}
		if stateHMACSecret == "" {
			missing = append(missing, "STATE_HMAC_SECRET")
		}
		if len(missing) > 0 {
			log.Fatalf("auth is enabled but required env vars are missing: %s", strings.Join(missing, ", "))
		}
	}

	// Derive frontendURL from VICE_BASE_URL env var. The pod hostname is the
	// subdomain hash set by app-exposer, so combining it with the base URL
	// produces the full analysis URL.
	var frontendURL string
	if baseURL := os.Getenv("VICE_BASE_URL"); baseURL != "" {
		hostname, err := os.Hostname()
		if err != nil {
			log.Fatalf("failed to get hostname for VICE_BASE_URL: %v", err)
		}
		parsedBase, err := url.Parse(baseURL)
		if err != nil {
			log.Fatalf("failed to parse VICE_BASE_URL %q: %v", baseURL, err)
		}
		parsedBase.Host = fmt.Sprintf("%s.%s", hostname, parsedBase.Host)
		frontendURL = parsedBase.String()
		log.Infof("derived frontend URL from VICE_BASE_URL: %s", frontendURL)
	}

	if frontendURL == "" {
		log.Fatal("VICE_BASE_URL env var must be set")
	}

	useSSL := false
	if *sslCert != "" || *sslKey != "" {
		if *sslCert == "" {
			log.Fatal("--ssl-cert is required with --ssl-key.")
		}

		if *sslKey == "" {
			log.Fatal("--ssl-key is required with --ssl-cert.")
		}
		useSSL = true
	}

	// Derive CORS origins from VICE_BASE_URL domain.
	var corsOrigins originFlags
	if viceBase := os.Getenv("VICE_BASE_URL"); viceBase != "" {
		if parsedBase, err := url.Parse(viceBase); err == nil && parsedBase.Host != "" {
			corsOrigins = originFlags{
				fmt.Sprintf("*.%s", parsedBase.Host),
				parsedBase.Host,
			}
		} else {
			log.Warnf("VICE_BASE_URL %q could not be parsed for CORS origins, using defaults", viceBase)
		}
	}
	if len(corsOrigins) < 1 {
		corsOrigins = originFlags{"*.cyverse.run", "*.cyverse.org", "*.cyverse.run:4343", "cyverse.run", "cyverse.run:4343"}
	}

	if *analysisID == "" {
		log.Fatal("--analysis-id must be set.")
	}

	log.Infof("backend URL is %s", *backendURL)
	log.Infof("websocket backend URL is %s", *wsbackendURL)
	log.Infof("frontend URL is %s", frontendURL)
	log.Infof("listen address is %s", *listenAddr)
	log.Infof("Keycloak base URL is %s", keycloakBaseURL)
	log.Infof("Keycloak realm is %s", keycloakRealm)
	log.Infof("Keycloak client ID is %s", keycloakClientID)
	log.Infof("Keycloak client secret is set: %v", keycloakClientSecret != "")
	log.Infof("read timeout is %s", *encodedReadTimeout)
	log.Infof("write timeout is %s", *encodedWriteTimeout)
	log.Infof("idle timeout is %s", *encodedIdleTimeout)
	log.Infof("authentication disabled: %v", disableAuth)
	log.Infof("admin entitlements: %v", adminEntitlements)

	for _, origin := range corsOrigins {
		log.Infof("CORS origin: %s", origin)
	}

	authkey := make([]byte, 64)
	_, err := rand.Read(authkey)
	if err != nil {
		log.Fatal(err)
	}

	sessionStore := sessions.NewCookieStore(authkey)
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   *maxAge,
		HttpOnly: true,
		// The login flow returns the browser to this app via a cross-site
		// top-level redirect (Keycloak, then the vice-operator relay), so the
		// state cookie must survive a SameSite=Lax navigation. Secure is gated
		// on the deployment actually serving HTTPS.
		SameSite: http.SameSiteLaxMode,
		Secure:   strings.HasPrefix(frontendURL, "https://"),
	}

	// Decode the timeout duration for back-channel requests to the identity provider.
	ssoTimeout, err := time.ParseDuration(*encodedSSOTimeout)
	if err != nil {
		log.Fatalf("invalid timeout duration for back-channel requests to the IdP: %s", err.Error())
	}

	// Decode the timeout durations for the HTTP server.
	readTimeout, err := time.ParseDuration(*encodedReadTimeout)
	if err != nil {
		log.Fatalf("invalid read timeout duration: %s", err.Error())
	}

	writeTimeout, err := time.ParseDuration(*encodedWriteTimeout)
	if err != nil {
		log.Fatalf("invalid write timeout duration: %s", err.Error())
	}

	idleTimeout, err := time.ParseDuration(*encodedIdleTimeout)
	if err != nil {
		log.Fatalf("invalid idle timeout duration: %s", err.Error())
	}

	// Create an HTTP client to use for back-channel requests to the identity provider.
	client := &http.Client{
		Timeout: ssoTimeout,
	}

	// Parse the JWKS cache TTL.
	jwksCacheTTL, err := time.ParseDuration(*encodedJWKSCacheTTL)
	if err != nil {
		log.Fatalf("invalid JWKS cache TTL duration: %s", err.Error())
	}

	p := &VICEProxy{
		keycloakBaseURL:      keycloakBaseURL,
		keycloakRealm:        keycloakRealm,
		keycloakClientID:     keycloakClientID,
		keycloakClientSecret: keycloakClientSecret,
		frontendURL:          frontendURL,
		backendURL:           *backendURL,
		wsbackendURL:         *wsbackendURL,
		resourceName:         *analysisID,
		sessionStore:         sessionStore,
		ssoClient:            *client,
		disableAuth:          disableAuth,
		adminEntitlements:    adminEntitlements,
		operatorCallbackURL:  operatorCallbackURL,
		stateCodec:           viceauth.NewCodec([]byte(stateHMACSecret)),
	}

	// Load the initial allowed-users list from the permissions ConfigMap mount.
	// If the file doesn't exist yet (e.g. in dev), log an error but continue —
	// the watcher will pick it up when the volume is mounted.
	if !disableAuth {
		count, err := p.loadAllowedUsers(permissionsFilePath)
		if err != nil {
			log.Errorf("could not load initial permissions: %v", err)
		} else {
			log.Infof("loaded %d allowed users from %s", count, permissionsFilePath)
		}
		if err := p.watchPermissionsFile(permissionsFilePath); err != nil {
			log.Fatalf("permissions file watcher failed (proxy cannot pick up permission changes): %v", err)
		}
	}

	// Set up JWKS caching if auth is enabled and TTL is positive.
	if !disableAuth && jwksCacheTTL > 0 {
		certsURL, err := p.KeycloakURL("certs")
		if err != nil {
			log.Fatalf("failed to build Keycloak certs URL: %s", err.Error())
		}
		p.jwksCertsURL = certsURL.String()

		ar := jwk.NewAutoRefresh(context.Background())
		ar.Configure(p.jwksCertsURL, jwk.WithMinRefreshInterval(jwksCacheTTL))

		p.jwksAutoRefresh = ar
		log.Infof("JWKS caching enabled with minimum refresh interval of %s", jwksCacheTTL)
	} else if !disableAuth {
		log.Info("JWKS caching disabled, certificates will be fetched on every token validation")
	}

	proxy, err := p.Proxy()
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()

	// Unauthenticated endpoints — health check and internal info.
	r.PathPrefix("/url-ready").HandlerFunc(p.URLIsReady)
	r.Path("/frontend-url").Methods(http.MethodGet).HandlerFunc(p.FrontendURL)

	// Operator-facing session management endpoints — unauthenticated because
	// they're called by the vice-operator over the in-cluster Service, not by
	// end users through the browser.
	r.Path("/active-sessions").Methods("GET").HandlerFunc(p.HandleActiveSessions)
	r.Path("/logout-user").Methods("POST").HandlerFunc(p.HandleLogoutUser)

	// Conditionally add authentication routes based on DISABLE_AUTH env var.
	if !disableAuth {
		// If the query contains a code parameter, handle the OAuth authorization code
		r.PathPrefix("/").Queries("code", "").Handler(http.HandlerFunc(p.HandleAuthorizationCode))
		// If the request doesn't have a valid session, redirect to Keycloak for authentication
		r.PathPrefix("/").MatcherFunc(p.Session).Handler(http.HandlerFunc(p.RequireKeycloakAuth))
	}

	// Proxy all requests to the backend
	r.PathPrefix("/").Handler(proxy)

	c := cors.New(cors.Options{
		AllowedOrigins:   corsOrigins,
		AllowCredentials: true,
	})

	server := &http.Server{
		Handler:      c.Handler(r),
		Addr:         *listenAddr,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
	if useSSL {
		err = server.ListenAndServeTLS(*sslCert, *sslKey)
	} else {
		err = server.ListenAndServe()
	}
	log.Fatal(err)
}
