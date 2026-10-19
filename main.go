package main

import (
	"context"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed static/*
var assets embed.FS

type application struct {
	auth    *Authenticator
	manager *Manager
	slots   chan struct{}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func result(w http.ResponseWriter, value any, err error) {
	if err == nil {
		reply(w, http.StatusOK, map[string]any{"data": value})
		return
	}
	var failure *ManagerError
	if errors.As(err, &failure) {
		reply(w, failure.Status, map[string]string{"error": failure.Message})
		return
	}
	// Do not log upstream bodies, request headers, credentials or request paths.
	log.Print("management operation unavailable")
	reply(w, http.StatusServiceUnavailable, map[string]string{"error": "操作暂时不可用，请稍后使用相同请求重试"})
}

func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		reply(w, 415, map[string]string{"error": "请使用 JSON 请求"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		reply(w, 400, map[string]string{"error": "请求内容无效"})
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		reply(w, 400, map[string]string{"error": "请求内容无效"})
		return false
	}
	return true
}

func (a *application) static(w http.ResponseWriter, r *http.Request, file, contentType, main, admin string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		reply(w, 405, map[string]string{"error": "请求方法无效"})
		return
	}
	body, err := assets.ReadFile("static/" + file)
	if err != nil {
		reply(w, 503, map[string]string{"error": "页面暂时不可用"})
		return
	}
	body = []byte(strings.NewReplacer("{{MAIN_ORIGIN}}", "https://"+main, "{{ADMIN_ORIGIN}}", "https://"+admin).Replace(string(body)))
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(200)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (a *application) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if r.URL.Path == "/healthz" {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			reply(w, 200, map[string]string{"status": "ok"})
			return
		}
	}
	if main, ok := a.auth.MainForAdmin(r.Host); ok {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; frame-src https://"+main+"; base-uri 'none'; frame-ancestors 'none'")
		if r.URL.Path == "/" {
			a.static(w, r, "wrapper.html", "text/html; charset=utf-8", main, authHost(r.Host))
			return
		}
		if r.URL.Path == "/wrapper.css" {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			_, _ = io.WriteString(w, "html,body{height:100%;margin:0}iframe{display:block;width:100%;height:100%;border:0}noscript{font:14px monospace}")
			return
		}
		reply(w, 404, map[string]string{"error": "页面不存在"})
		return
	}
	admin, ok := a.auth.AdminForMain(r.Host)
	if !ok {
		reply(w, 403, map[string]string{"error": "请求来源无效"})
		return
	}
	main := authHost(r.Host)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors https://"+admin)
	switch r.URL.Path {
	case "/__keymgr/frame":
		a.static(w, r, "frame.html", "text/html; charset=utf-8", main, admin)
		return
	case "/__keymgr/frame.js":
		a.static(w, r, "frame.js", "text/javascript; charset=utf-8", main, admin)
		return
	case "/__keymgr/app.js":
		a.static(w, r, "app.js", "text/javascript; charset=utf-8", main, admin)
		return
	case "/__keymgr/style.css":
		a.static(w, r, "style.css", "text/css; charset=utf-8", main, admin)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/__keymgr/api/") {
		reply(w, 404, map[string]string{"error": "接口不存在"})
		return
	}
	if len(r.URL.RawQuery) > 2048 {
		reply(w, 400, map[string]string{"error": "请求无效"})
		return
	}
	identity, allowed := a.auth.Require(w, r)
	if !allowed {
		return
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		reply(w, 503, map[string]string{"error": "操作繁忙，请稍后重试"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/__keymgr/api/")
	switch {
	case path == "panel" && r.Method == http.MethodGet:
		a.static(w, r, "panel.html", "text/html; charset=utf-8", main, admin)
	case path == "session" && r.Method == http.MethodGet:
		reply(w, 200, map[string]any{"data": map[string]any{"user": map[string]any{"id": identity.UserID, "email": identity.Email, "role": "admin", "concurrency": identity.Concurrency}, "dedicated_users": true, "concurrency_enabled": true}})
	case path == "groups" && r.Method == http.MethodGet:
		value, err := a.manager.Groups(r.Context(), identity)
		result(w, value, err)
	case path == "batches" && r.Method == http.MethodGet:
		value, err := a.manager.PendingBatches(r.Context(), identity)
		result(w, value, err)
	case path == "keys/search" && r.Method == http.MethodPost:
		var body SearchRequest
		if !decode(w, r, &body) {
			return
		}
		value, err := a.manager.List(r.Context(), identity, body)
		result(w, value, err)
	case path == "keys" && r.Method == http.MethodGet:
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		value, err := a.manager.List(r.Context(), identity, SearchRequest{Page: page, PageSize: size, Status: r.URL.Query().Get("status")})
		result(w, value, err)
	case path == "keys/batch" && r.Method == http.MethodPost:
		var body BatchRequest
		if !decode(w, r, &body) {
			return
		}
		value, err := a.manager.Batch(r.Context(), identity, body)
		result(w, value, err)
	case strings.HasPrefix(path, "keys/") && r.Method == http.MethodPut:
		id, err := strconv.ParseInt(strings.TrimPrefix(path, "keys/"), 10, 64)
		if err != nil || id <= 0 {
			reply(w, 400, map[string]string{"error": "Key 编号无效"})
			return
		}
		var body UpdateRequest
		if !decode(w, r, &body) {
			return
		}
		value, err := a.manager.Update(r.Context(), identity, id, body)
		result(w, value, err)
	default:
		reply(w, 404, map[string]string{"error": "接口或请求方法不存在"})
	}
}

func main() {
	log.SetFlags(0)
	listen := env("KEY_MANAGEMENT_LISTEN", "127.0.0.1:8091")
	host, _, err := net.SplitHostPort(listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("listen address must be loopback")
	}
	master, err := hex.DecodeString(os.Getenv("KEY_MANAGEMENT_MASTER_KEY"))
	if err != nil || len(master) != 32 {
		log.Fatal("a fixed 32-byte master key is required")
	}
	upstream := env("KEY_MANAGEMENT_UPSTREAM", "http://127.0.0.1:8080")
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	auth, err := NewAuthenticator(AuthConfig{UpstreamURL: upstream, Client: client, MainToAdmin: map[string]string{"tmallmodels.com": "admin.tmallmodels.com", "manyai.icu": "admin.manyai.icu"}})
	if err != nil {
		log.Fatal("invalid authentication configuration")
	}
	store, err := NewStateStore(env("KEY_MANAGEMENT_STATE", "/var/lib/sub2api-key-management/state.json"))
	if err != nil {
		log.Fatal("cannot load management state")
	}
	manager := NewManager(upstream, store, master, client)
	if helper := os.Getenv("KEY_MANAGEMENT_KEY_HELPER"); helper != "" {
		manager.SetKeyStore(NewCommandKeyStore(helper))
	}
	app := &application{auth: auth, manager: manager, slots: make(chan struct{}, 16)}
	server := &http.Server{Addr: listen, Handler: app, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 10 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768, ErrorLog: log.New(io.Discard, "", 0)}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	fmt.Printf("Key management service listening on %s\n", listen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("management listener stopped")
	}
}
