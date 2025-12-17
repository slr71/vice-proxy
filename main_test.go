package main

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
)

// getVICEProxy returns a VICEProxy instance with some default settnigs for testing. Some fields that aren't being used
// during testing are omitted.
func getVICEProxy() *VICEProxy {
	// Create a session store for testing
	authkey := make([]byte, 64)
	_, _ = rand.Read(authkey)
	sessionStore := sessions.NewCookieStore(authkey)

	return &VICEProxy{
		keycloakBaseURL:         "https://keycloak.example.org",
		keycloakRealm:           "example",
		keycloakClientID:        "example-client",
		keycloakClientSecret:    "example-secret",
		frontendURL:             "https://foobarbaz.example.run",
		backendURL:              "http://localhost:8888",
		wsbackendURL:            "http://localhost:8888",
		getAnalysisIDBase:       "http://get-analysis-id",
		checkResourceAccessBase: "http://check-resource-access",
		sessionStore:            sessionStore,
		disableAuth:             false,
	}
}

type KeycloakURLTest struct {
	description string
	components  []string
	expected    string
}

func TestKeycloakURL(t *testing.T) {
	tests := []KeycloakURLTest{
		{
			description: "no additional components",
			components:  []string{},
			expected:    "https://keycloak.example.org/realms/example/protocol/openid-connect",
		},
		{
			description: "one additional component",
			components:  []string{"foo"},
			expected:    "https://keycloak.example.org/realms/example/protocol/openid-connect/foo",
		},
		{
			description: "multiple additional components",
			components:  []string{"foo", "bar", "baz"},
			expected:    "https://keycloak.example.org/realms/example/protocol/openid-connect/foo/bar/baz",
		},
		{
			description: "components that require encoding",
			components:  []string{"foo bar"},
			expected:    "https://keycloak.example.org/realms/example/protocol/openid-connect/foo%20bar",
		},
	}

	// Run the tests.
	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			assert := assert.New(t)
			proxy := getVICEProxy()

			// Build the actual URL.
			actualURL, err := proxy.KeycloakURL(test.components...)
			assert.NoError(err, "keycloakURL should not return an error")
			assert.Equal(test.expected, actualURL.String(), "the actual URL should equal the expected URL")
		})
	}
}

func TestProxyWithAuthDisabled(t *testing.T) {
	assert := assert.New(t)

	// Create a test backend server
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	// Create proxy with auth disabled
	proxy := getVICEProxy()
	proxy.disableAuth = true
	proxy.backendURL = backend.URL

	// Get the proxy handler
	proxyHandler, err := proxy.Proxy()
	assert.NoError(err, "creating proxy handler should not error")

	// Create a test request without authentication
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	// Execute the request
	proxyHandler.ServeHTTP(w, req)

	// Verify the backend was called and request succeeded
	assert.True(backendCalled, "backend should have been called")
	assert.Equal(http.StatusOK, w.Code, "request should succeed without authentication")
}

func TestProxyWithAuthEnabled(t *testing.T) {
	assert := assert.New(t)

	// Create a test backend server
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	// Create proxy with auth enabled (default)
	proxy := getVICEProxy()
	proxy.disableAuth = false
	proxy.backendURL = backend.URL

	// Get the proxy handler
	proxyHandler, err := proxy.Proxy()
	assert.NoError(err, "creating proxy handler should not error")

	// Create a test request without authentication
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	// Execute the request
	proxyHandler.ServeHTTP(w, req)

	// Verify the backend was NOT called and request was rejected
	assert.False(backendCalled, "backend should not have been called without authentication")
	assert.Equal(http.StatusForbidden, w.Code, "request should be rejected without authentication")
}

func TestAuthenticateAndAuthorizeWithoutSession(t *testing.T) {
	assert := assert.New(t)

	proxy := getVICEProxy()
	proxy.resourceName = "test-resource"

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	// Attempt authentication without a valid session
	username, err := proxy.authenticateAndAuthorize(w, req)

	// Should fail with empty username and error
	assert.Empty(username, "username should be empty without a valid session")
	assert.Error(err, "should return an error without a valid session")
}

func TestDisableAuthFlag(t *testing.T) {
	assert := assert.New(t)

	// Test that disableAuth field defaults to false
	proxy := getVICEProxy()
	assert.False(proxy.disableAuth, "disableAuth should default to false")

	// Test that disableAuth can be set to true
	proxy.disableAuth = true
	assert.True(proxy.disableAuth, "disableAuth should be settable to true")
}
