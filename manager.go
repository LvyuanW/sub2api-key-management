package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// State contains identifiers and operation progress only. Native wallets, keys,
// credentials, and authentication sessions remain owned by sub2api.
type ManagerState struct {
	Records []ManagedRecord `json:"records"`
	Batches []ManagedBatch  `json:"batches"`
	Updates []ManagedUpdate `json:"updates"`
}

type ManagedRecord struct {
	Nonce          string    `json:"nonce"`
	AdminID        int64     `json:"admin_id"`
	UserID         int64     `json:"user_id"`
	KeyID          int64     `json:"key_id"`
	Name           string    `json:"name"`
	BatchID        string    `json:"batch_id"`
	Index          int       `json:"index"`
	CreatedAt      time.Time `json:"created_at"`
	InitialBalance float64   `json:"initial_balance"`
	GroupID        int64     `json:"group_id"`
	ExpiresAt      string    `json:"expires_at"`
	Concurrency    int       `json:"concurrency"`
	Stage          string    `json:"stage"`
}

type ManagedBatch struct {
	ID           string        `json:"id"`
	AdminID      int64         `json:"admin_id"`
	PayloadHash  string        `json:"payload_hash"`
	RecordNonces []string      `json:"record_nonces"`
	CreatedAt    time.Time     `json:"created_at"`
	Request      *BatchRequest `json:"request,omitempty"`
}

// An operation is recorded before any wallet write. Once a financial request
// has an ambiguous outcome it is never automatically sent a second time.
type ManagedUpdate struct {
	AdminID        int64     `json:"admin_id"`
	KeyID          int64     `json:"key_id"`
	RequestID      string    `json:"request_id"`
	PayloadHash    string    `json:"payload_hash"`
	UserDone       bool      `json:"user_done"`
	KeyDone        bool      `json:"key_done"`
	BalanceStarted bool      `json:"balance_started"`
	BalanceDone    bool      `json:"balance_done"`
	BalanceMode    string    `json:"balance_mode,omitempty"`
	BalanceAmount  float64   `json:"balance_amount,omitempty"`
	Done           bool      `json:"done"`
	CreatedAt      time.Time `json:"created_at"`
}

type SearchRequest struct {
	Search   string `json:"search"`
	Status   string `json:"status"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

type BatchRequest struct {
	RequestID   string  `json:"request_id"`
	Count       int     `json:"count"`
	NamePrefix  string  `json:"name_prefix"`
	GroupID     int64   `json:"group_id"`
	Quota       float64 `json:"quota"`
	ExpiresAt   string  `json:"expires_at"`
	Concurrency int     `json:"concurrency"`
}

type BalanceAction struct {
	Mode   string  `json:"mode"`
	Amount float64 `json:"amount"`
}

type UpdateRequest struct {
	RequestID     string         `json:"request_id"`
	Name          *string        `json:"name,omitempty"`
	GroupID       *int64         `json:"group_id,omitempty"`
	ExpiresAt     *string        `json:"expires_at,omitempty"`
	Status        *string        `json:"status,omitempty"`
	Concurrency   *int           `json:"concurrency,omitempty"`
	BalanceAction *BalanceAction `json:"balance_action,omitempty"`
}

type Group struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Status           string `json:"status"`
	Platform         string `json:"platform"`
	SubscriptionType string `json:"subscription_type"`
}

type nativeUser struct {
	ID            int64   `json:"id"`
	Email         string  `json:"email"`
	Role          string  `json:"role"`
	Status        string  `json:"status"`
	Notes         string  `json:"notes"`
	Balance       float64 `json:"balance"`
	Concurrency   int     `json:"concurrency"`
	AllowedGroups []int64 `json:"allowed_groups"`
}

type NativeKey struct {
	ID                 int64      `json:"id"`
	UserID             int64      `json:"user_id"`
	Key                string     `json:"key"`
	Name               string     `json:"name"`
	GroupID            *int64     `json:"group_id"`
	Group              *Group     `json:"group,omitempty"`
	Status             string     `json:"status"`
	Quota              float64    `json:"quota"`
	QuotaUsed          float64    `json:"quota_used"`
	ExpiresAt          *time.Time `json:"expires_at"`
	LastUsedAt         *time.Time `json:"last_used_at"`
	CreatedAt          time.Time  `json:"created_at"`
	CurrentConcurrency int        `json:"current_concurrency"`
}

type KeyView struct {
	NativeKey
	WalletBalance    float64 `json:"wallet_balance"`
	ConcurrencyLimit int     `json:"concurrency_limit"`
	ManagedUserID    int64   `json:"managed_user_id"`
	UserStatus       string  `json:"user_status"`
}

type ListResponse struct {
	Items    []KeyView `json:"items"`
	Total    int       `json:"total"`
	Page     int       `json:"page"`
	PageSize int       `json:"page_size"`
	Pages    int       `json:"pages"`
}

type BatchItem struct {
	Index int      `json:"index"`
	Name  string   `json:"name"`
	Key   *KeyView `json:"key,omitempty"`
	Error string   `json:"error,omitempty"`
}

type BatchResponse struct {
	RequestID string      `json:"request_id"`
	Items     []BatchItem `json:"items"`
	Succeeded int         `json:"succeeded"`
	Failed    int         `json:"failed"`
}

type PendingBatch struct {
	Request   BatchRequest `json:"request"`
	Total     int          `json:"total"`
	Ready     int          `json:"ready"`
	Pending   int          `json:"pending"`
	CreatedAt time.Time    `json:"created_at"`
}

type ManagerError struct {
	Status  int    `json:"-"`
	Message string `json:"error"`
}

func (e *ManagerError) Error() string { return e.Message }

func managerError(status int, message string) *ManagerError {
	return &ManagerError{Status: status, Message: message}
}

type tokenEntry struct {
	Token   string
	Expires time.Time
}

// KeyStore supplies only the Key operations absent from sub2api's administrator
// HTTP API. It never manages native user wallets, user roles, or concurrency.
// A successful write includes acknowledgement of authentication-cache invalidation.
type KeyStore interface {
	Create(context.Context, ManagedRecord, string) (NativeKey, error)
	Update(context.Context, ManagedRecord, string, map[string]any) error
}

type Manager struct {
	upstream string
	store    *StateStore
	master   []byte
	client   *http.Client
	opMu     sync.Mutex
	tokenMu  sync.Mutex
	tokens   map[string]tokenEntry
	// Kept private so integration tests can exercise retry/cancellation without
	// waiting a minute. Production uses the native login limiter's one-minute window.
	batchRetryDelay time.Duration
	batchMaxRetries int
	keyStore        KeyStore
}

// SetKeyStore is called once during application startup, before serving requests.
func (m *Manager) SetKeyStore(store KeyStore) { m.keyStore = store }

func NewManager(upstream string, store *StateStore, master []byte, client *http.Client) *Manager {
	c := http.Client{Timeout: 20 * time.Second}
	if client != nil {
		c = *client
	}
	if c.Timeout <= 0 || c.Timeout > 30*time.Second {
		c.Timeout = 20 * time.Second
	}
	c.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &Manager{upstream: strings.TrimSuffix(upstream, "/"), store: store,
		master: append([]byte(nil), master...), client: &c, tokens: make(map[string]tokenEntry),
		batchRetryDelay: 61 * time.Second, batchMaxRetries: 5}
}

func (m *Manager) derive(label, nonce string) string {
	h := hmac.New(sha256.New, m.master)
	h.Write([]byte(label + ":" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

func (m *Manager) password(r ManagedRecord) string { return "Km!" + m.derive("pass", r.Nonce) }
func (m *Manager) apiKey(r ManagedRecord) string   { return "sk-" + m.derive("key", r.Nonce) }
func managedEmail(r ManagedRecord) string          { return "km-" + r.Nonce + "@keymgr.invalid" }
func managedNotes(r ManagedRecord) string {
	return fmt.Sprintf("sub2api-key-management owner=%d nonce=%s", r.AdminID, r.Nonce)
}

func stableHash(value any) string {
	b, _ := json.Marshal(value)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func validRequestID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validMoney(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1e9
}

func validName(value string) bool {
	if strings.TrimSpace(value) == "" || len([]rune(html.EscapeString(value))) > 100 {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func validExpiry(value string) bool {
	if value == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, value)
	return err == nil && t.Year() >= 1970 && t.Year() <= 9999
}

// call never returns native response text: error messages may contain a key,
// password, or a SQL error. Only known HTTP categories reach the browser.
func (m *Manager) call(ctx context.Context, s *AdminSession, token, method, path string, body, out any, idempotency string) error {
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return managerError(400, "请求参数无效")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, m.upstream+path, bytes.NewReader(data))
	if err != nil {
		return managerError(503, "主站连接暂时不可用")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if s != nil {
		req.Header.Set("User-Agent", s.UserAgent)
		req.Header.Set("X-Real-IP", s.ClientIP)
		req.Header.Set("X-Forwarded-For", s.ClientIP)
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	if idempotency != "" {
		req.Header.Set("Idempotency-Key", idempotency)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return managerError(503, "主站请求未确认完成；请重试原操作，不要重复充值")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		switch resp.StatusCode {
		case 400:
			return managerError(400, "主站拒绝请求，请检查参数、分组权限及可用余额")
		case 401:
			return managerError(401, "主站会话失效，请重新登录管理员账号")
		case 403:
			return managerError(403, "主站拒绝访问，请检查账号状态、验证码及后台模式设置")
		case 404:
			return managerError(404, "主站中没有对应记录")
		case 409:
			return managerError(409, "主站记录或操作发生冲突，请稍后重试原操作")
		case 423, 451:
			return managerError(423, "请先在主站管理后台由管理员本人确认官方使用声明")
		case 429:
			return managerError(429, "主站请求频率受限，请至少等待一分钟后重试原批次或原操作")
		default:
			return managerError(502, "主站返回异常，操作可能尚未完成，请重试原操作")
		}
	}
	var envelope struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&envelope); err != nil || envelope.Code != 0 || len(envelope.Data) == 0 {
		return managerError(502, "主站响应格式异常，操作可能尚未完成")
	}
	if out != nil {
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return managerError(502, "主站响应格式异常，操作可能尚未完成")
		}
	}
	return nil
}

func (m *Manager) Groups(ctx context.Context, s *AdminSession) ([]Group, error) {
	var groups []Group
	if err := m.call(ctx, s, s.Token, "GET", "/api/v1/admin/groups/all", nil, &groups, ""); err != nil {
		return nil, err
	}
	result := make([]Group, 0, len(groups))
	for _, group := range groups {
		if group.Status == "active" && group.SubscriptionType == "standard" {
			result = append(result, group)
		}
	}
	return result, nil
}

func (m *Manager) checkGroup(ctx context.Context, s *AdminSession, id int64) error {
	groups, err := m.Groups(ctx, s)
	if err != nil {
		return err
	}
	for _, g := range groups {
		if g.ID == id {
			return nil
		}
	}
	return managerError(400, "请选择启用的按余额计费分组；本服务不创建订阅用户")
}

func (m *Manager) checkCarrierLogin(ctx context.Context, s *AdminSession) error {
	if m.keyStore != nil {
		if checker, ok := m.keyStore.(interface{ Check(context.Context) error }); ok {
			if err := checker.Check(ctx); err != nil {
				return managerError(503, "Key 存储或缓存连接检查失败，已停止创建充值用户")
			}
		}
		return nil
	}
	var settings struct {
		BackendMode *bool `json:"backend_mode_enabled"`
		Turnstile   bool  `json:"turnstile_enabled"`
		Tencent     bool  `json:"tencent_captcha_enabled"`
		Aliyun      bool  `json:"aliyun_captcha_enabled"`
	}
	if err := m.call(ctx, s, s.Token, "GET", "/api/v1/settings/public", nil, &settings, ""); err != nil {
		return err
	}
	if settings.BackendMode == nil {
		return managerError(409, "主站公开设置缺少用户登录模式信息，已停止创建独立用户")
	}
	if *settings.BackendMode {
		return managerError(409, "主站已启用仅管理员登录模式，独立用户无法创建或修改 Key；请先在主站关闭该模式")
	}
	if settings.Turnstile || settings.Tencent || settings.Aliyun {
		return managerError(409, "主站登录验证码已启用，独立用户无法自动登录；已停止创建以避免留下未完成的充值用户")
	}
	return nil
}

func (m *Manager) snapshot() (ManagerState, error) {
	s, err := m.store.Snapshot()
	if err != nil {
		return ManagerState{}, managerError(503, "管理状态读取失败")
	}
	return s, nil
}

func (m *Manager) save(fn func(*ManagerState) error) error {
	if err := m.store.Update(fn); err != nil {
		var me *ManagerError
		if errors.As(err, &me) {
			return err
		}
		return managerError(503, "管理状态保存失败，请保留原操作编号后重试")
	}
	return nil
}

func findRecord(state ManagerState, admin, keyID int64) (ManagedRecord, bool) {
	for _, record := range state.Records {
		if record.AdminID == admin && record.KeyID == keyID && keyID > 0 {
			return record, true
		}
	}
	return ManagedRecord{}, false
}

func (m *Manager) saveRecord(record ManagedRecord) error {
	return m.save(func(state *ManagerState) error {
		for i := range state.Records {
			if state.Records[i].Nonce == record.Nonce && state.Records[i].AdminID == record.AdminID {
				state.Records[i] = record
				return nil
			}
		}
		return managerError(409, "管理记录已改变，请重试原操作")
	})
}

// PendingBatches restores the exact original request after a page refresh or
// lost connection. Resuming it cannot fund an already-created native user again.
func (m *Manager) PendingBatches(ctx context.Context, s *AdminSession) ([]PendingBatch, error) {
	state, err := m.snapshot()
	if err != nil {
		return nil, err
	}
	result := []PendingBatch{}
	for _, batch := range state.Batches {
		if batch.AdminID != s.UserID {
			continue
		}
		item := PendingBatch{Total: len(batch.RecordNonces), CreatedAt: batch.CreatedAt}
		var first *ManagedRecord
		for i := range state.Records {
			r := &state.Records[i]
			if r.AdminID == s.UserID && r.BatchID == batch.ID {
				if first == nil {
					first = r
				}
				if r.Stage == "ready" {
					item.Ready++
				}
			}
		}
		item.Pending = item.Total - item.Ready
		if item.Pending <= 0 {
			continue
		}
		if batch.Request != nil {
			item.Request = *batch.Request
		} else if first != nil {
			// Recover metadata written by the first service build, before the
			// original payload was retained explicitly.
			item.Request = BatchRequest{RequestID: batch.ID, Count: item.Total,
				NamePrefix: strings.TrimSuffix(first.Name, fmt.Sprintf("-%03d", first.Index)),
				GroupID:    first.GroupID, Quota: first.InitialBalance, ExpiresAt: first.ExpiresAt, Concurrency: first.Concurrency}
		} else {
			return nil, managerError(409, "未完成批次的管理记录不完整，请从备份恢复")
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result, nil
}

func (m *Manager) user(ctx context.Context, s *AdminSession, record ManagedRecord) (nativeUser, error) {
	var user nativeUser
	if record.UserID <= 0 || record.AdminID != s.UserID {
		return user, managerError(404, "没有可管理的 Key")
	}
	if err := m.call(ctx, s, s.Token, "GET", fmt.Sprintf("/api/v1/admin/users/%d", record.UserID), nil, &user, ""); err != nil {
		return user, err
	}
	if user.ID != record.UserID || user.Email != managedEmail(record) || user.Notes != managedNotes(record) || user.Role != "user" {
		return user, managerError(409, "独立用户身份已被修改，停止自动管理")
	}
	return user, nil
}

func (m *Manager) keys(ctx context.Context, s *AdminSession, record ManagedRecord) ([]NativeKey, error) {
	var page struct {
		Items []NativeKey `json:"items"`
		Total int         `json:"total"`
	}
	path := fmt.Sprintf("/api/v1/admin/users/%d/api-keys?page=1&page_size=100", record.UserID)
	if err := m.call(ctx, s, s.Token, "GET", path, nil, &page, ""); err != nil {
		return nil, err
	}
	if page.Total > 1 || len(page.Items) > 1 {
		return nil, managerError(409, "此独立用户出现多个 Key，停止自动管理以保护余额隔离")
	}
	for _, key := range page.Items {
		if key.UserID != record.UserID || key.Key != m.apiKey(record) {
			return nil, managerError(409, "独立用户的 Key 已被替换，停止自动管理")
		}
	}
	return page.Items, nil
}

func (m *Manager) view(ctx context.Context, s *AdminSession, record ManagedRecord) (KeyView, error) {
	var result KeyView
	user, err := m.user(ctx, s, record)
	if err != nil {
		return result, err
	}
	keys, err := m.keys(ctx, s, record)
	if err != nil {
		return result, err
	}
	if len(keys) != 1 || keys[0].ID != record.KeyID {
		return result, managerError(404, "对应 Key 已被删除，请检查主站")
	}
	return KeyView{NativeKey: keys[0], WalletBalance: user.Balance,
		ConcurrencyLimit: user.Concurrency, ManagedUserID: user.ID, UserStatus: user.Status}, nil
}

func (m *Manager) List(ctx context.Context, s *AdminSession, req SearchRequest) (ListResponse, error) {
	result := ListResponse{Items: []KeyView{}, Page: req.Page, PageSize: req.PageSize}
	if req.Page > 1000000 || req.Page < 0 || req.PageSize < 0 || req.PageSize > 100 {
		return result, managerError(400, "分页参数超出范围")
	}
	if result.Page < 1 {
		result.Page = 1
	}
	if result.PageSize < 1 || result.PageSize > 100 {
		result.PageSize = 25
	}
	if len(req.Search) > 512 {
		return result, managerError(400, "搜索内容过长")
	}
	state, err := m.snapshot()
	if err != nil {
		return result, err
	}
	search := strings.ToLower(strings.TrimSpace(req.Search))
	var records []ManagedRecord
	for _, record := range state.Records {
		if record.AdminID == s.UserID && record.KeyID > 0 && record.Stage == "ready" &&
			(search == "" || strings.Contains(strings.ToLower(record.Name), search) || strings.Contains(m.apiKey(record), search) || strconv.FormatInt(record.KeyID, 10) == search) {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].KeyID > records[j].KeyID })
	// Native status changes as keys expire or are exhausted, so status filtering
	// must inspect native records instead of a stale status saved by this service.
	var selected []KeyView
	for i, record := range records {
		if req.Status == "" && (i < (result.Page-1)*result.PageSize || i >= result.Page*result.PageSize) {
			continue
		}
		view, err := m.view(ctx, s, record)
		if err != nil {
			return result, err
		}
		if req.Status == "" || view.Status == req.Status {
			selected = append(selected, view)
		}
	}
	result.Total = len(records)
	if req.Status != "" {
		result.Total = len(selected)
		start := (result.Page - 1) * result.PageSize
		if start > len(selected) {
			start = len(selected)
		}
		end := start + result.PageSize
		if end > len(selected) {
			end = len(selected)
		}
		selected = selected[start:end]
	}
	result.Pages = (result.Total + result.PageSize - 1) / result.PageSize
	if result.Pages < 1 {
		result.Pages = 1
	}
	if selected != nil {
		result.Items = selected
	}
	return result, nil
}

func (m *Manager) ownerToken(ctx context.Context, s *AdminSession, record ManagedRecord) (string, error) {
	cacheKey := stableHash([]string{strconv.FormatInt(record.UserID, 10), s.ClientIP, s.UserAgent})
	m.tokenMu.Lock()
	entry, ok := m.tokens[cacheKey]
	m.tokenMu.Unlock()
	if ok && time.Now().Before(entry.Expires) {
		return entry.Token, nil
	}
	var result struct {
		AccessToken string     `json:"access_token"`
		ExpiresIn   int        `json:"expires_in"`
		Requires2FA bool       `json:"requires_2fa"`
		User        nativeUser `json:"user"`
	}
	if err := m.call(ctx, s, "", "POST", "/api/v1/auth/login", map[string]any{"email": managedEmail(record), "password": m.password(record)}, &result, ""); err != nil {
		var me *ManagerError
		if errors.As(err, &me) && (me.Status == 401 || me.Status == 403) {
			return "", managerError(409, "独立用户登录失败，请检查其密码、状态，以及主站验证码或后台模式设置")
		}
		return "", err
	}
	if result.Requires2FA || result.AccessToken == "" || result.User.ID != record.UserID || result.User.Role != "user" {
		return "", managerError(409, "独立用户认证状态已改变，请检查主站账号")
	}
	ttl := 10 * time.Minute
	if result.ExpiresIn > 0 && time.Duration(result.ExpiresIn)*time.Second < ttl {
		ttl = time.Duration(result.ExpiresIn) * time.Second
	}
	m.tokenMu.Lock()
	for key, cached := range m.tokens {
		if time.Now().After(cached.Expires) {
			delete(m.tokens, key)
		}
	}
	m.tokens[cacheKey] = tokenEntry{Token: result.AccessToken, Expires: time.Now().Add(ttl - 5*time.Second)}
	m.tokenMu.Unlock()
	return result.AccessToken, nil
}

func (m *Manager) callOwner(ctx context.Context, s *AdminSession, record ManagedRecord, token, method, path string, body, out any, idempotency string) error {
	err := m.call(ctx, s, token, method, path, body, out, idempotency)
	var me *ManagerError
	if errors.As(err, &me) && me.Status == 401 {
		cacheKey := stableHash([]string{strconv.FormatInt(record.UserID, 10), s.ClientIP, s.UserAgent})
		m.tokenMu.Lock()
		delete(m.tokens, cacheKey)
		m.tokenMu.Unlock()
		return managerError(409, "独立用户会话失效，请重试原操作；若仍失败请检查该用户密码")
	}
	return err
}

func (m *Manager) Batch(ctx context.Context, s *AdminSession, req BatchRequest) (BatchResponse, error) {
	result := BatchResponse{RequestID: req.RequestID, Items: []BatchItem{}}
	if !validRequestID(req.RequestID) || req.Count < 1 || req.Count > 100 || !validName(req.NamePrefix) || !validName(req.NamePrefix+"-100") || len([]rune(req.NamePrefix)) > 80 ||
		req.GroupID <= 0 || !validMoney(req.Quota) || !validExpiry(req.ExpiresAt) || req.Concurrency < 1 || req.Concurrency > 10000 {
		return result, managerError(400, "批量参数无效：数量 1–100，并发 1–10000，金额非负且不超过 10 亿 ¥")
	}
	m.opMu.Lock()
	defer m.opMu.Unlock()
	if err := m.checkCarrierLogin(ctx, s); err != nil {
		return result, err
	}
	if err := m.checkGroup(ctx, s, req.GroupID); err != nil {
		return result, err
	}
	payload := req
	payload.RequestID = ""
	hash := stableHash(payload)
	if err := m.save(func(state *ManagerState) error {
		for _, batch := range state.Batches {
			if batch.ID == req.RequestID && batch.AdminID == s.UserID {
				if batch.PayloadHash != hash {
					return managerError(409, "原批次编号不能用于不同参数；请使用新的批次编号")
				}
				return nil
			}
		}
		savedRequest := req
		batch := ManagedBatch{ID: req.RequestID, AdminID: s.UserID, PayloadHash: hash, CreatedAt: time.Now().UTC(), Request: &savedRequest}
		for i := 1; i <= req.Count; i++ {
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return err
			}
			r := ManagedRecord{Nonce: hex.EncodeToString(nonce[:]), AdminID: s.UserID, Name: fmt.Sprintf("%s-%03d", req.NamePrefix, i),
				BatchID: req.RequestID, Index: i, CreatedAt: time.Now().UTC(), InitialBalance: req.Quota, GroupID: req.GroupID,
				ExpiresAt: req.ExpiresAt, Concurrency: req.Concurrency, Stage: "pending"}
			batch.RecordNonces = append(batch.RecordNonces, r.Nonce)
			state.Records = append(state.Records, r)
		}
		state.Batches = append(state.Batches, batch)
		return nil
	}); err != nil {
		return result, err
	}
	state, err := m.snapshot()
	if err != nil {
		return result, err
	}
	blocked := ""
	retries := 0
	retryDeadline := time.Now().Add(8 * time.Minute)
	for _, record := range state.Records {
		if record.AdminID != s.UserID || record.BatchID != req.RequestID {
			continue
		}
		item := BatchItem{Index: record.Index, Name: record.Name}
		if blocked != "" && record.Stage != "ready" {
			item.Error = blocked
		} else {
			view, err := m.resumeRecord(ctx, s, record)
			for err != nil && retries < m.batchMaxRetries {
				var limited *ManagerError
				if !errors.As(err, &limited) || limited.Status != 429 || time.Now().Add(m.batchRetryDelay).After(retryDeadline) {
					break
				}
				retries++
				timer := time.NewTimer(m.batchRetryDelay)
				select {
				case <-ctx.Done():
					timer.Stop()
					err = managerError(503, "批次等待已中止，已保留完成项目；请重试原批次")
				case <-timer.C:
					fresh, stateErr := m.snapshot()
					if stateErr != nil {
						err = stateErr
						break
					}
					for _, saved := range fresh.Records {
						if saved.AdminID == s.UserID && saved.Nonce == record.Nonce {
							record = saved
							break
						}
					}
					view, err = m.resumeRecord(ctx, s, record)
				}
				if ctx.Err() != nil {
					break
				}
			}
			if err != nil {
				item.Error = err.Error()
				var me *ManagerError
				if errors.As(err, &me) && (me.Status == 429 || me.Status == 423 || me.Status >= 500) {
					blocked = item.Error
				}
			} else {
				item.Key = &view
			}
		}
		if item.Error == "" {
			result.Succeeded++
		} else {
			result.Failed++
		}
		result.Items = append(result.Items, item)
	}
	sort.Slice(result.Items, func(i, j int) bool { return result.Items[i].Index < result.Items[j].Index })
	return result, nil
}

func (m *Manager) resumeRecord(ctx context.Context, s *AdminSession, record ManagedRecord) (KeyView, error) {
	if record.Stage == "ready" {
		return m.view(ctx, s, record)
	}
	if record.UserID == 0 {
		// The deterministic email recovers a user created immediately before a
		// timeout or crash. Its initial wallet is never funded a second time.
		var matches struct {
			Items []nativeUser `json:"items"`
		}
		path := "/api/v1/admin/users?page=1&page_size=100&search=" + url.QueryEscape(managedEmail(record))
		if err := m.call(ctx, s, s.Token, "GET", path, nil, &matches, ""); err != nil {
			return KeyView{}, err
		}
		for _, u := range matches.Items {
			if u.Email == managedEmail(record) {
				if u.Notes != managedNotes(record) || u.Role != "user" {
					return KeyView{}, managerError(409, "独立用户邮箱已被其他记录占用")
				}
				record.UserID = u.ID
			}
		}
		if record.UserID == 0 {
			var user nativeUser
			body := map[string]any{"email": managedEmail(record), "password": m.password(record), "username": record.Name,
				"notes": managedNotes(record), "role": "user", "balance": record.InitialBalance, "concurrency": record.Concurrency,
				"allowed_groups": []int64{record.GroupID}, "restrict_public_groups": true, "rpm_limit": 0}
			if err := m.call(ctx, s, s.Token, "POST", "/api/v1/admin/users", body, &user, ""); err != nil {
				return KeyView{}, err
			}
			if user.ID <= 0 || user.Email != managedEmail(record) || user.Role != "user" {
				return KeyView{}, managerError(502, "独立用户创建响应无效，请重试原批次")
			}
			record.UserID = user.ID
		}
		record.Stage = "user_created"
		if err := m.saveRecord(record); err != nil {
			return KeyView{}, err
		}
	}
	if _, err := m.user(ctx, s, record); err != nil {
		return KeyView{}, err
	}
	keys, err := m.keys(ctx, s, record)
	if err != nil {
		return KeyView{}, err
	}
	if len(keys) == 1 {
		if record.KeyID != 0 && record.KeyID != keys[0].ID {
			return KeyView{}, managerError(409, "独立 Key 已被替换")
		}
		record.KeyID = keys[0].ID
	}
	var token string
	if m.keyStore != nil {
		// Create also acknowledges cache invalidation when recovering a row
		// committed before a timeout. Existing native credit is never recreated.
		key, err := m.keyStore.Create(ctx, record, m.apiKey(record))
		if err != nil {
			return KeyView{}, managerError(503, "Key 数据创建或缓存同步未确认完成，请重试原批次")
		}
		if key.ID <= 0 || key.UserID != record.UserID || key.Key != m.apiKey(record) || (record.KeyID > 0 && record.KeyID != key.ID) {
			return KeyView{}, managerError(409, "独立 Key 的数据归属校验失败，已停止自动管理")
		}
		record.KeyID = key.ID
	} else {
		token, err = m.ownerToken(ctx, s, record)
		if err != nil {
			return KeyView{}, err
		}
	}
	if m.keyStore == nil && record.KeyID == 0 {
		var key NativeKey
		body := map[string]any{"name": record.Name, "group_id": record.GroupID, "custom_key": m.apiKey(record), "quota": 0}
		if err := m.callOwner(ctx, s, record, token, "POST", "/api/v1/keys", body, &key, "km-create-"+record.Nonce); err != nil {
			return KeyView{}, err
		}
		if key.ID <= 0 || key.UserID != record.UserID || key.Key != m.apiKey(record) {
			return KeyView{}, managerError(502, "独立 Key 创建响应无效，请重试原批次")
		}
		record.KeyID = key.ID
	}
	record.Stage = "key_created"
	if err := m.saveRecord(record); err != nil {
		return KeyView{}, err
	}
	if m.keyStore != nil {
		if record.ExpiresAt != "" {
			if err := m.keyStore.Update(ctx, record, m.apiKey(record), map[string]any{"expires_at": record.ExpiresAt}); err != nil {
				return KeyView{}, managerError(503, "Key 有效期写入或缓存同步未确认完成，请重试原批次")
			}
		}
		// Group permissions remain in the official administrator service. Bind
		// after all helper writes so even a same-group request synchronously
		// clears the running sub2api process's L1 authentication cache.
		if err := m.adminKeyGroup(ctx, s, record.KeyID, record.GroupID); err != nil {
			return KeyView{}, err
		}
	} else if record.ExpiresAt != "" {
		var key NativeKey
		if err := m.callOwner(ctx, s, record, token, "PUT", fmt.Sprintf("/api/v1/keys/%d", record.KeyID), map[string]any{"expires_at": record.ExpiresAt}, &key, ""); err != nil {
			return KeyView{}, err
		}
	}
	record.Stage = "ready"
	if err := m.saveRecord(record); err != nil {
		return KeyView{}, err
	}
	return m.view(ctx, s, record)
}

func (m *Manager) adminKeyGroup(ctx context.Context, s *AdminSession, keyID, groupID int64) error {
	var result struct {
		APIKey NativeKey `json:"api_key"`
	}
	if err := m.call(ctx, s, s.Token, "PUT", fmt.Sprintf("/api/v1/admin/api-keys/%d", keyID), map[string]any{"group_id": groupID}, &result, ""); err != nil {
		return err
	}
	if result.APIKey.ID != keyID || result.APIKey.GroupID == nil || *result.APIKey.GroupID != groupID {
		return managerError(502, "主站分组更新响应无效，请重试原操作")
	}
	return nil
}

func (m *Manager) saveUpdate(operation ManagedUpdate) error {
	return m.save(func(state *ManagerState) error {
		for i := range state.Updates {
			if state.Updates[i].AdminID == operation.AdminID && state.Updates[i].RequestID == operation.RequestID {
				state.Updates[i] = operation
				return nil
			}
		}
		state.Updates = append(state.Updates, operation)
		return nil
	})
}

func (m *Manager) Update(ctx context.Context, s *AdminSession, keyID int64, req UpdateRequest) (KeyView, error) {
	if !validRequestID(req.RequestID) || keyID <= 0 ||
		(req.Name != nil && !validName(*req.Name)) || (req.ExpiresAt != nil && !validExpiry(*req.ExpiresAt)) ||
		(req.Status != nil && *req.Status != "active" && *req.Status != "inactive") ||
		(req.Concurrency != nil && (*req.Concurrency < 1 || *req.Concurrency > 10000)) || (req.GroupID != nil && *req.GroupID <= 0) {
		return KeyView{}, managerError(400, "修改参数无效")
	}
	if req.BalanceAction != nil && (!validMoney(req.BalanceAction.Amount) ||
		(req.BalanceAction.Mode != "add" && req.BalanceAction.Mode != "subtract" && req.BalanceAction.Mode != "set")) {
		return KeyView{}, managerError(400, "余额操作无效")
	}
	m.opMu.Lock()
	defer m.opMu.Unlock()
	state, err := m.snapshot()
	if err != nil {
		return KeyView{}, err
	}
	record, ok := findRecord(state, s.UserID, keyID)
	if !ok {
		return KeyView{}, managerError(404, "没有可管理的 Key")
	}
	payload := req
	payload.RequestID = ""
	hash := stableHash(payload)
	operation := ManagedUpdate{AdminID: s.UserID, KeyID: keyID, RequestID: req.RequestID, PayloadHash: hash, CreatedAt: time.Now().UTC()}
	for _, existing := range state.Updates {
		if existing.AdminID == s.UserID && existing.RequestID == req.RequestID {
			if existing.KeyID != keyID || existing.PayloadHash != hash {
				return KeyView{}, managerError(409, "原操作编号不能用于不同参数，请刷新页面后发起新操作")
			}
			operation = existing
		}
	}
	if operation.Done {
		return m.view(ctx, s, record)
	}
	if operation.BalanceStarted && !operation.BalanceDone {
		return KeyView{}, managerError(409, "上次余额变更结果未确认，已阻止重复扣款或充值；请在主站核对余额变更记录后处理")
	}
	view, err := m.view(ctx, s, record)
	if err != nil {
		return KeyView{}, err
	}
	if view.UserStatus != "active" {
		return KeyView{}, managerError(409, "独立用户已在主站被停用，请先检查该账号")
	}
	if req.BalanceAction != nil && req.BalanceAction.Mode == "subtract" && req.BalanceAction.Amount > view.WalletBalance {
		return KeyView{}, managerError(400, "扣减金额超过该 Key 当前可用余额")
	}
	if req.GroupID != nil {
		if err := m.checkGroup(ctx, s, *req.GroupID); err != nil {
			return KeyView{}, err
		}
	}
	if err := m.saveUpdate(operation); err != nil {
		return KeyView{}, err
	}
	if !operation.UserDone {
		body := map[string]any{}
		if req.Concurrency != nil {
			body["concurrency"] = *req.Concurrency
		}
		if req.GroupID != nil {
			user, err := m.user(ctx, s, record)
			if err != nil {
				return KeyView{}, err
			}
			groups := append([]int64(nil), user.AllowedGroups...)
			found := false
			for _, group := range groups {
				found = found || group == *req.GroupID
			}
			if !found {
				groups = append(groups, *req.GroupID)
			}
			body["allowed_groups"] = groups
		}
		if len(body) > 0 {
			var user nativeUser
			if err := m.call(ctx, s, s.Token, "PUT", fmt.Sprintf("/api/v1/admin/users/%d", record.UserID), body, &user, ""); err != nil {
				return KeyView{}, err
			}
		}
		operation.UserDone = true
		if err := m.saveUpdate(operation); err != nil {
			return KeyView{}, err
		}
	}
	if !operation.KeyDone {
		body := map[string]any{}
		if req.Name != nil {
			body["name"] = *req.Name
		}
		if req.GroupID != nil && m.keyStore == nil {
			body["group_id"] = *req.GroupID
		}
		if req.ExpiresAt != nil {
			body["expires_at"] = *req.ExpiresAt
		}
		if req.Status != nil {
			body["status"] = *req.Status
		}
		barrierGroup := int64(0)
		if req.GroupID != nil {
			barrierGroup = *req.GroupID
		} else if view.GroupID != nil {
			barrierGroup = *view.GroupID
		}
		if m.keyStore != nil && len(body) > 0 && barrierGroup <= 0 {
			return KeyView{}, managerError(409, "Key 当前未绑定分组，请选择有效分组后重试")
		}
		if len(body) > 0 {
			if m.keyStore != nil {
				if err := m.keyStore.Update(ctx, record, m.apiKey(record), body); err != nil {
					return KeyView{}, managerError(503, "Key 数据修改或缓存同步未确认完成，请重试原操作")
				}
			} else {
				token, err := m.ownerToken(ctx, s, record)
				if err != nil {
					return KeyView{}, err
				}
				var key NativeKey
				if err := m.callOwner(ctx, s, record, token, "PUT", fmt.Sprintf("/api/v1/keys/%d", keyID), body, &key, ""); err != nil {
					return KeyView{}, err
				}
			}
		}
		if m.keyStore != nil && (req.GroupID != nil || len(body) > 0) {
			// Redis publication only confirms receipt, not that the local L1
			// subscriber has processed it. The official same-group write clears
			// this process's L1 before KeyDone or any wallet mutation advances.
			if err := m.adminKeyGroup(ctx, s, keyID, barrierGroup); err != nil {
				return KeyView{}, err
			}
		}
		operation.KeyDone = true
		if err := m.saveUpdate(operation); err != nil {
			return KeyView{}, err
		}
	}
	if req.BalanceAction != nil && !operation.BalanceDone {
		mode, amount := req.BalanceAction.Mode, req.BalanceAction.Amount
		// sub2api's balance endpoint rejects zero. To clear a wallet, subtract
		// its current balance atomically. A concurrent debit makes this fail
		// instead of overwriting a newer balance or restoring spent credit.
		if operation.BalanceMode != "" {
			mode, amount = operation.BalanceMode, operation.BalanceAmount
		} else if mode == "set" && amount == 0 {
			user, err := m.user(ctx, s, record)
			if err != nil {
				return KeyView{}, err
			}
			mode, amount = "subtract", user.Balance
			if amount < 0 {
				mode, amount = "add", -amount
			}
		}
		if amount > 0 {
			operation.BalanceStarted, operation.BalanceMode, operation.BalanceAmount = true, mode, amount
			if err := m.saveUpdate(operation); err != nil {
				return KeyView{}, err
			}
			var user nativeUser
			id := "km-wallet-" + stableHash([]any{s.UserID, keyID, req.RequestID})
			body := map[string]any{"operation": mode, "balance": amount, "notes": id}
			if err := m.call(ctx, s, s.Token, "POST", fmt.Sprintf("/api/v1/admin/users/%d/balance", record.UserID), body, &user, id); err != nil {
				var me *ManagerError
				if errors.As(err, &me) && me.Status < 500 && me.Status != 409 {
					operation.BalanceStarted = false // known rejected before success
					if saveErr := m.saveUpdate(operation); saveErr != nil {
						return KeyView{}, saveErr
					}
				}
				return KeyView{}, err
			}
		}
		operation.BalanceDone = true
		if err := m.saveUpdate(operation); err != nil {
			return KeyView{}, err
		}
	}
	if req.Name != nil {
		record.Name = *req.Name
	}
	operation.Done = true
	// Finalize the local search name and operation receipt together: a crash
	// cannot retain a completed receipt alongside a permanently stale name.
	if err := m.save(func(state *ManagerState) error {
		for i := range state.Records {
			if state.Records[i].Nonce == record.Nonce && state.Records[i].AdminID == record.AdminID {
				state.Records[i] = record
			}
		}
		for i := range state.Updates {
			if state.Updates[i].AdminID == operation.AdminID && state.Updates[i].RequestID == operation.RequestID {
				state.Updates[i] = operation
			}
		}
		return nil
	}); err != nil {
		return KeyView{}, err
	}
	return m.view(ctx, s, record)
}
