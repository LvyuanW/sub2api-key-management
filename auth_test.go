package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const authTestToken = "sensitive-jwt-must-not-be-echoed"

type authTransportFunc func(*http.Request) (*http.Response, error)

func (fn authTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func authTestConfig(upstream string) AuthConfig {
	return AuthConfig{MainToAdmin: map[string]string{"tmallmodels.com": "admin.tmallmodels.com", "manyai.icu": "admin.manyai.icu"}, UpstreamURL: upstream}
}

func authTestRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://tmallmodels.com/__keymgr/api/panel", nil)
	r.RemoteAddr = "127.0.0.1:34567"
	r.Header.Set("Authorization", "Bearer "+authTestToken)
	r.Header.Set("User-Agent", "browser-user-agent")
	r.Header.Set("X-Real-IP", "203.0.113.17")
	return r
}

func TestAuthVerifiedFreshAndPreservesBrowserFingerprint(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/api/v1/auth/me" ||
			r.Header.Get("Authorization") != "Bearer "+authTestToken ||
			r.UserAgent() != "browser-user-agent" || r.Header.Get("X-Real-IP") != "203.0.113.17" ||
			r.Header.Get("X-Forwarded-For") != "203.0.113.17" || r.Host != "tmallmodels.com" {
			t.Error("authentication request did not preserve expected endpoint and fingerprint")
		}
		io.WriteString(w, `{"code":0,"data":{"id":5,"email":"admin@example.com","role":"admin","status":"active","concurrency":10}}`)
	}))
	defer upstream.Close()
	a, err := NewAuthenticator(authTestConfig(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		w := httptest.NewRecorder()
		identity, ok := a.Require(w, authTestRequest())
		if !ok || identity == nil || identity.UserID != 5 || identity.Token != authTestToken || identity.Concurrency != 10 {
			t.Fatal("valid administrator rejected")
		}
		data, _ := json.Marshal(identity)
		if strings.Contains(string(data), authTestToken) {
			t.Fatal("token leaked through JSON identity")
		}
		if w.Body.Len() != 0 {
			t.Fatal("successful verifier unexpectedly wrote a response")
		}
	}
	if calls.Load() != 2 {
		t.Fatal("identity must be verified against upstream for every request")
	}
}

func TestAuthDeniesMissingCredentialWrongHostAndWrongOriginWithoutUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { t.Error("upstream must not be called") }))
	defer upstream.Close()
	a, _ := NewAuthenticator(authTestConfig(upstream.URL))
	tests := []struct {
		name   string
		change func(*http.Request)
		want   int
	}{
		{"missing", func(r *http.Request) { r.Header.Del("Authorization") }, 401},
		{"basic", func(r *http.Request) { r.Header.Set("Authorization", "Basic nope") }, 401},
		{"oversized", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 8192)) }, 401},
		{"wrong-host", func(r *http.Request) { r.Host = "evil.invalid" }, 403},
		{"admin-host", func(r *http.Request) { r.Host = "admin.tmallmodels.com" }, 403},
		{"wrong-origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.invalid") }, 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := authTestRequest()
			tt.change(r)
			w := httptest.NewRecorder()
			identity, ok := a.Require(w, r)
			if ok || identity != nil || w.Code != tt.want {
				t.Fatalf("got allowed=%v code=%d", ok, w.Code)
			}
			if strings.Contains(w.Body.String(), authTestToken) {
				t.Fatal("credential in error response")
			}
			if w.Header().Get("X-Keymgr-Auth-Required") != "1" {
				t.Fatal("auth denial needs a distinct marker from operation-level failures")
			}
		})
	}
}

func TestAuthRequiresActiveAdminAndFailsClosedOnMalformedUpstream(t *testing.T) {
	for _, tt := range []struct {
		name, body   string
		status, want int
	}{
		{"ordinary-user", `{"code":0,"data":{"id":2,"role":"user","status":"active"}}`, 200, 403},
		{"disabled-admin", `{"code":0,"data":{"id":2,"role":"admin","status":"disabled"}}`, 200, 403},
		{"expired", `{"error":"TOKEN_EXPIRED secret detail"}`, 401, 401},
		{"broken-json", `not-json secret detail`, 200, 503},
		{"missing-status", `{"code":0,"data":{"id":2,"role":"admin"}}`, 200, 403},
		{"missing-code", `{"data":{"id":2,"role":"admin","status":"active"}}`, 200, 503},
		{"nonzero-code", `{"code":1,"data":{"id":2,"role":"admin","status":"active"}}`, 200, 503},
		{"upstream-down", `secret detail`, 500, 503},
	} {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tt.status); io.WriteString(w, tt.body) }))
			defer upstream.Close()
			a, _ := NewAuthenticator(authTestConfig(upstream.URL))
			w := httptest.NewRecorder()
			identity, ok := a.Require(w, authTestRequest())
			if ok || identity != nil || w.Code != tt.want {
				t.Fatalf("allowed=%v code=%d want=%d", ok, w.Code, tt.want)
			}
			if strings.Contains(w.Body.String(), "secret detail") || strings.Contains(w.Body.String(), authTestToken) {
				t.Fatal("upstream details leaked")
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("auth response can be cached")
			}
		})
	}
}

func TestAuthNeverFollowsUpstreamRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { t.Error("credential followed a redirect") }))
	defer target.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer upstream.Close()
	a, _ := NewAuthenticator(authTestConfig(upstream.URL))
	w := httptest.NewRecorder()
	if identity, ok := a.Require(w, authTestRequest()); identity != nil || ok || w.Code != 503 {
		t.Fatal("redirect accepted")
	}
}

func TestAuthClientIPTrustsOnlyLoopbackProxy(t *testing.T) {
	a, _ := NewAuthenticator(authTestConfig("http://127.0.0.1:8080"))
	r := authTestRequest()
	if a.ClientIP(r) != "203.0.113.17" {
		t.Fatal("loopback proxy IP not accepted")
	}
	r.RemoteAddr = "198.51.100.7:1234"
	if a.ClientIP(r) != "198.51.100.7" {
		t.Fatal("untrusted source spoofed IP")
	}
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Real-IP", "invalid, 203.0.113.8")
	if a.ClientIP(r) != "127.0.0.1" {
		t.Fatal("malformed proxy IP accepted")
	}
}

func TestAuthConfigRejectsUnsafePairsAndUpstreamCredentials(t *testing.T) {
	for _, cfg := range []AuthConfig{
		{MainToAdmin: map[string]string{"main.example": "same.invalid/path"}, UpstreamURL: "http://127.0.0.1"},
		{MainToAdmin: map[string]string{"same.example": "same.example"}, UpstreamURL: "http://127.0.0.1"},
		{MainToAdmin: map[string]string{"main.example": "admin.example"}, UpstreamURL: "http://user:secret@127.0.0.1"},
		{MainToAdmin: map[string]string{"main.example": "admin.example"}, UpstreamURL: "http://127.0.0.1?token=secret"},
	} {
		if _, err := NewAuthenticator(cfg); err == nil {
			t.Fatal("unsafe authentication configuration accepted")
		}
	}
}

func TestAuthTransportPanicFailsClosedWithoutSecretDetails(t *testing.T) {
	cfg := authTestConfig("http://127.0.0.1:8080")
	cfg.Client = &http.Client{Transport: authTransportFunc(func(*http.Request) (*http.Response, error) {
		panic("sensitive transport error must not escape")
	})}
	a, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	identity, ok := a.Require(w, authTestRequest())
	if ok || identity != nil || w.Code != 503 {
		t.Fatal("authentication transport panic must fail closed")
	}
	if strings.Contains(w.Body.String(), "sensitive") || strings.Count(w.Body.String(), "error") != 1 {
		t.Fatal("panic details or duplicate errors escaped")
	}
}
