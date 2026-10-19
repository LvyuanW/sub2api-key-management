package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AuthConfig lists fixed host pairs. Authentication remains owned by sub2api.
type AuthConfig struct {
	MainToAdmin map[string]string
	UpstreamURL string
	Client      *http.Client
}

// AdminSession describes this request's verified identity. No session is cached.
// The bearer token and fingerprint are never included in a JSON response.
type AdminSession struct {
	UserID      int64  `json:"user_id"`
	Email       string `json:"email"`
	Token       string `json:"-"`
	ClientIP    string `json:"-"`
	UserAgent   string `json:"-"`
	Concurrency int    `json:"concurrency"`
}

type Authenticator struct {
	mainToAdmin map[string]string
	adminToMain map[string]string
	upstream    string
	client      *http.Client
}

func authHost(value string) string {
	value = strings.ToLower(value)
	if strings.HasSuffix(value, ":443") {
		value = strings.TrimSuffix(value, ":443")
	}
	return value
}

func validAuthHost(host string) bool {
	if host == "" || strings.ContainsAny(host, ":/?#@\\ \t\r\n") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, c := range host {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func NewAuthenticator(cfg AuthConfig) (*Authenticator, error) {
	base, err := url.Parse(cfg.UpstreamURL)
	if err != nil || base == nil || (base.Scheme != "http" && base.Scheme != "https") ||
		base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		(base.Path != "" && base.Path != "/") {
		return nil, errors.New("invalid authentication upstream origin")
	}
	a := &Authenticator{mainToAdmin: map[string]string{}, adminToMain: map[string]string{},
		upstream: strings.TrimSuffix(base.String(), "/")}
	for main, admin := range cfg.MainToAdmin {
		main, admin = strings.ToLower(main), strings.ToLower(admin)
		if !validAuthHost(main) || !validAuthHost(admin) || main == admin {
			return nil, errors.New("invalid authentication host pair")
		}
		if _, exists := a.adminToMain[admin]; exists {
			return nil, errors.New("duplicate authentication admin host")
		}
		if _, exists := a.mainToAdmin[main]; exists {
			return nil, errors.New("duplicate authentication main host")
		}
		a.mainToAdmin[main], a.adminToMain[admin] = admin, main
	}
	if len(a.mainToAdmin) == 0 {
		return nil, errors.New("authentication host pairs are required")
	}
	for main := range a.mainToAdmin {
		if _, overlaps := a.adminToMain[main]; overlaps {
			return nil, errors.New("authentication host roles overlap")
		}
	}
	client := http.Client{Timeout: 5 * time.Second}
	if cfg.Client != nil {
		client = *cfg.Client
		if client.Timeout <= 0 || client.Timeout > 5*time.Second {
			client.Timeout = 5 * time.Second
		}
	}
	// Never forward a bearer credential to an upstream redirect target.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	a.client = &client
	return a, nil
}

func (a *Authenticator) MainForAdmin(host string) (string, bool) {
	value, ok := a.adminToMain[authHost(host)]
	return value, ok
}

func (a *Authenticator) AdminForMain(host string) (string, bool) {
	value, ok := a.mainToAdmin[authHost(host)]
	return value, ok
}

func (a *Authenticator) IsMainRequest(r *http.Request) bool {
	_, ok := a.AdminForMain(r.Host)
	return ok
}

func (a *Authenticator) IsAdminRequest(r *http.Request) bool {
	_, ok := a.MainForAdmin(r.Host)
	return ok
}

// ClientIP accepts nginx's overwritten X-Real-IP only over a loopback connection.
// Incoming X-Forwarded-For is deliberately not trusted.
func (a *Authenticator) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote := net.ParseIP(host)
	if remote == nil {
		return ""
	}
	if remote.IsLoopback() {
		values := r.Header.Values("X-Real-IP")
		if len(values) == 1 {
			if real := net.ParseIP(strings.TrimSpace(values[0])); real != nil {
				return real.String()
			}
		}
	}
	return remote.String()
}

func writeAuthError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		w.Header().Set("X-Keymgr-Auth-Required", "1")
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Require verifies the main-origin bearer token against sub2api for every call.
// It does not decode JWT claims locally, read a static admin key, or retain JWTs.
func (a *Authenticator) Require(w http.ResponseWriter, r *http.Request) (identity *AdminSession, allowed bool) {
	defer func() {
		if recover() != nil {
			identity, allowed = nil, false
			writeAuthError(w, http.StatusServiceUnavailable, "身份验证暂时不可用")
		}
	}()
	if !a.IsMainRequest(r) {
		writeAuthError(w, http.StatusForbidden, "请求来源无效")
		return nil, false
	}
	origin := r.Header.Get("Origin")
	if origin != "" && origin != "https://"+authHost(r.Host) {
		writeAuthError(w, http.StatusForbidden, "请求来源无效")
		return nil, false
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 8192 {
		writeAuthError(w, http.StatusUnauthorized, "请先在主站以管理员身份登录")
		return nil, false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		writeAuthError(w, http.StatusUnauthorized, "请先在主站以管理员身份登录")
		return nil, false
	}
	clientIP := a.ClientIP(r)
	if clientIP == "" {
		writeAuthError(w, http.StatusBadRequest, "请求来源无效")
		return nil, false
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, a.upstream+"/api/v1/auth/me", nil)
	if err != nil {
		writeAuthError(w, http.StatusServiceUnavailable, "身份验证暂时不可用")
		return nil, false
	}
	request.Header.Set("Authorization", "Bearer "+parts[1])
	request.Header.Set("User-Agent", r.UserAgent())
	request.Header.Set("X-Real-IP", clientIP)
	request.Header.Set("X-Forwarded-For", clientIP)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Host = authHost(r.Host)
	response, err := a.client.Do(request)
	if err != nil {
		writeAuthError(w, http.StatusServiceUnavailable, "身份验证暂时不可用")
		return nil, false
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		writeAuthError(w, http.StatusUnauthorized, "主站登录已失效，请重新登录")
		return nil, false
	}
	if response.StatusCode == http.StatusForbidden {
		writeAuthError(w, http.StatusForbidden, "仅限主站管理员访问")
		return nil, false
	}
	if response.StatusCode != http.StatusOK {
		writeAuthError(w, http.StatusServiceUnavailable, "身份验证暂时不可用")
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 {
		writeAuthError(w, http.StatusServiceUnavailable, "身份验证暂时不可用")
		return nil, false
	}
	var profile struct {
		Code json.RawMessage `json:"code"`
		Data *struct {
			ID          int64  `json:"id"`
			Email       string `json:"email"`
			Role        string `json:"role"`
			Status      string `json:"status"`
			Concurrency int    `json:"concurrency"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &profile) != nil || !bytes.Equal(bytes.TrimSpace(profile.Code), []byte("0")) ||
		profile.Data == nil || profile.Data.ID <= 0 {
		writeAuthError(w, http.StatusServiceUnavailable, "身份验证暂时不可用")
		return nil, false
	}
	if profile.Data.Role != "admin" || profile.Data.Status != "active" {
		writeAuthError(w, http.StatusForbidden, "仅限主站有效管理员访问")
		return nil, false
	}
	return &AdminSession{UserID: profile.Data.ID, Email: profile.Data.Email,
		Token: parts[1], ClientIP: clientIP, UserAgent: r.UserAgent(), Concurrency: profile.Data.Concurrency}, true
}
