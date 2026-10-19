package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// nativeFixture implements the official API boundary, including owner-scoped
// key writes, native wallets and failure-after-commit scenarios.
type nativeFixture struct {
	t                 *testing.T
	users             map[int64]nativeUser
	keys              map[int64]NativeKey
	passwords         map[int64]string
	userCreates       int
	keyCreates        int
	balanceWrites     int
	userWrites        int
	keyWrites         int
	logins            int
	loginLimit        int
	loginLimitOnce    bool
	onRateLimit       func()
	failUserCommitted bool
	failKeyCommitted  bool
	failBalanceCommit bool
	balanceRejectOnce bool
	lastBalance       map[string]any
	lastIdempotency   string
	lastKeyPatch      map[string]any
	backendMode       bool
	captchaEnabled    bool
}

func newManagerFixture(t *testing.T) (*Manager, *nativeFixture, *AdminSession) {
	t.Helper()
	f := &nativeFixture{t: t, users: map[int64]nativeUser{}, keys: map[int64]NativeKey{}, passwords: map[int64]string{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(srv.Close)
	store, err := NewStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(srv.URL, store, []byte(strings.Repeat("m", 32)), srv.Client())
	m.batchMaxRetries = 0 // Tests opt into a millisecond delay when exercising waits.
	s := &AdminSession{UserID: 1, Email: "admin@example.com", Token: "admin", ClientIP: "192.0.2.5", UserAgent: "manager-test"}
	return m, f, s
}

func nativeOK(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": value})
}

func nativeFailure(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": status, "message": "secret-native-password-or-key"})
}

func (f *nativeFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("User-Agent") != "manager-test" || r.Header.Get("X-Real-IP") != "192.0.2.5" || r.Header.Get("X-Forwarded-For") != "192.0.2.5" {
		f.t.Error("native calls must preserve the verified client fingerprint")
	}
	var body map[string]any
	if r.Body != nil && (r.Method == "PUT" || r.Method == "POST") {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.t.Errorf("invalid native JSON: %v", err)
		}
	}
	if r.URL.Path == "/api/v1/auth/login" {
		f.logins++
		if f.loginLimit > 0 && f.logins > f.loginLimit {
			if f.loginLimitOnce {
				f.loginLimit = 0
			}
			if f.onRateLimit != nil {
				f.onRateLimit()
			}
			nativeFailure(w, 429)
			return
		}
		for id, user := range f.users {
			if body["email"] == user.Email && body["password"] == f.passwords[id] {
				nativeOK(w, map[string]any{"access_token": fmt.Sprintf("owner-%d", id), "expires_in": 3600, "user": user})
				return
			}
		}
		nativeFailure(w, 401)
		return
	}
	if r.URL.Path == "/api/v1/settings/public" {
		nativeOK(w, map[string]any{"backend_mode_enabled": f.backendMode, "turnstile_enabled": f.captchaEnabled})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/admin/") && r.Header.Get("Authorization") != "Bearer admin" {
		f.t.Error("admin API must use the administrator's verified token")
		nativeFailure(w, 403)
		return
	}
	if r.URL.Path == "/api/v1/admin/groups/all" {
		nativeOK(w, []Group{{ID: 1, Name: "Wallet", Status: "active", SubscriptionType: "standard"}, {ID: 2, Name: "Other wallet", Status: "active", SubscriptionType: "standard"}, {ID: 3, Status: "active", SubscriptionType: "subscription"}, {ID: 4, Status: "disabled", SubscriptionType: "standard"}})
		return
	}
	if r.URL.Path == "/api/v1/admin/users" {
		if r.Method == "GET" {
			items := []nativeUser{}
			for _, u := range f.users {
				if strings.Contains(u.Email, r.URL.Query().Get("search")) {
					items = append(items, u)
				}
			}
			nativeOK(w, map[string]any{"items": items, "total": len(items)})
			return
		}
		f.userCreates++
		id := int64(f.userCreates + 10)
		u := nativeUser{ID: id, Email: body["email"].(string), Notes: body["notes"].(string), Role: body["role"].(string), Status: "active", Balance: body["balance"].(float64), Concurrency: int(body["concurrency"].(float64))}
		for _, group := range body["allowed_groups"].([]any) {
			u.AllowedGroups = append(u.AllowedGroups, int64(group.(float64)))
		}
		if body["restrict_public_groups"] != true || u.Role != "user" {
			f.t.Error("dedicated user must be a restricted ordinary user")
		}
		f.users[id], f.passwords[id] = u, body["password"].(string)
		if f.failUserCommitted {
			f.failUserCommitted = false
			nativeFailure(w, 500)
			return
		}
		nativeOK(w, u)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 5 && strings.HasPrefix(r.URL.Path, "/api/v1/admin/users/") {
		id, _ := strconv.ParseInt(parts[4], 10, 64)
		u, ok := f.users[id]
		if !ok {
			nativeFailure(w, 404)
			return
		}
		if len(parts) == 6 && parts[5] == "api-keys" {
			items := []NativeKey{}
			for _, k := range f.keys {
				if k.UserID == id {
					items = append(items, k)
				}
			}
			nativeOK(w, map[string]any{"items": items, "total": len(items)})
			return
		}
		if len(parts) == 6 && parts[5] == "balance" {
			f.balanceWrites++
			f.lastBalance, f.lastIdempotency = body, r.Header.Get("Idempotency-Key")
			if f.lastIdempotency == "" || body["notes"] != f.lastIdempotency {
				f.t.Error("wallet writes need a stable official idempotency key and audit note")
			}
			if f.balanceRejectOnce {
				f.balanceRejectOnce = false
				u.Balance -= 1
				f.users[id] = u
				nativeFailure(w, 400)
				return
			}
			amount := body["balance"].(float64)
			if amount <= 0 {
				f.t.Error("native balance API rejects zero/negative amount")
			}
			switch body["operation"] {
			case "add":
				u.Balance += amount
			case "subtract":
				if amount > u.Balance {
					nativeFailure(w, 400)
					return
				}
				u.Balance -= amount
			case "set":
				u.Balance = amount
			default:
				f.t.Error("unknown balance operation")
			}
			f.users[id] = u
			if f.failBalanceCommit {
				f.failBalanceCommit = false
				nativeFailure(w, 500)
				return
			}
			nativeOK(w, u)
			return
		}
		if r.Method == "PUT" {
			f.userWrites++
			if _, exists := body["balance"]; exists {
				f.t.Error("admin user update ignores balance: use atomic wallet endpoint")
			}
			if n, ok := body["concurrency"].(float64); ok {
				u.Concurrency = int(n)
			}
			if groups, ok := body["allowed_groups"].([]any); ok {
				u.AllowedGroups = nil
				for _, group := range groups {
					u.AllowedGroups = append(u.AllowedGroups, int64(group.(float64)))
				}
				for _, key := range f.keys {
					if key.UserID != id || key.GroupID == nil {
						continue
					}
					found := false
					for _, group := range u.AllowedGroups {
						found = found || group == *key.GroupID
					}
					if !found {
						f.t.Error("group change revoked the existing key before rebinding it")
					}
				}
			}
			f.users[id] = u
		}
		nativeOK(w, u)
		return
	}
	if r.URL.Path == "/api/v1/keys" && r.Method == "POST" {
		var userID int64
		fmt.Sscanf(r.Header.Get("Authorization"), "Bearer owner-%d", &userID)
		if userID == 0 {
			f.t.Error("key creation must authenticate its native owner")
			nativeFailure(w, 403)
			return
		}
		f.keyCreates++
		id, groupID := int64(100+f.keyCreates), int64(body["group_id"].(float64))
		key := NativeKey{ID: id, UserID: userID, Name: body["name"].(string), Key: body["custom_key"].(string), Quota: body["quota"].(float64), Status: "active", GroupID: &groupID, CreatedAt: time.Now().UTC()}
		if key.Quota != 0 {
			f.t.Error("dedicated key quota must remain unlimited: native wallet is the credit authority")
		}
		f.keys[id] = key
		if f.failKeyCommitted {
			f.failKeyCommitted = false
			nativeFailure(w, 500)
			return
		}
		nativeOK(w, key)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/keys/") && r.Method == "PUT" {
		id, _ := strconv.ParseInt(parts[3], 10, 64)
		key, ok := f.keys[id]
		if !ok {
			nativeFailure(w, 404)
			return
		}
		if r.Header.Get("Authorization") != fmt.Sprintf("Bearer owner-%d", key.UserID) {
			f.t.Error("key update must authenticate its native owner")
			nativeFailure(w, 403)
			return
		}
		f.keyWrites++
		f.lastKeyPatch = body
		if _, exists := body["reset_quota"]; exists {
			f.t.Error("ordinary edits must not erase consumption")
		}
		if _, exists := body["quota"]; exists {
			f.t.Error("wallet changes must not set a second native key budget")
		}
		if status, ok := body["status"].(string); ok {
			key.Status = status
		}
		if name, ok := body["name"].(string); ok {
			key.Name = name
		}
		if group, ok := body["group_id"].(float64); ok {
			id := int64(group)
			key.GroupID = &id
		}
		if expiry, ok := body["expires_at"].(string); ok {
			key.ExpiresAt = nil
			if expiry != "" {
				parsed, err := time.Parse(time.RFC3339, expiry)
				if err != nil {
					f.t.Fatal(err)
				}
				key.ExpiresAt = &parsed
			}
		}
		f.keys[id] = key
		nativeOK(w, key)
		return
	}
	f.t.Errorf("unexpected native endpoint %s %s", r.Method, r.URL.Path)
	nativeFailure(w, 404)
}

func batchInput(id string, count int) BatchRequest {
	return BatchRequest{RequestID: id, Count: count, NamePrefix: "实验", GroupID: 1, Quota: 5, ExpiresAt: "2030-01-02T03:04:05+08:00", Concurrency: 3}
}

func createOne(t *testing.T, m *Manager, s *AdminSession) KeyView {
	t.Helper()
	result, err := m.Batch(context.Background(), s, batchInput("batch-create-0001", 1))
	if err != nil || result.Succeeded != 1 || len(result.Items) != 1 || result.Items[0].Key == nil {
		t.Fatalf("create: result=%+v error=%v", result, err)
	}
	return *result.Items[0].Key
}

func TestManagerNativeWalletIsolationAndIdempotentEdits(t *testing.T) {
	m, f, s := newManagerFixture(t)
	request := batchInput("batch-isolated-0001", 2)
	result, err := m.Batch(context.Background(), s, request)
	if err != nil || result.Succeeded != 2 {
		t.Fatalf("batch: %+v %v", result, err)
	}
	first, second := *result.Items[0].Key, *result.Items[1].Key
	if first.ManagedUserID == second.ManagedUserID || first.WalletBalance != 5 || second.WalletBalance != 5 || first.ConcurrencyLimit != 3 {
		t.Fatal("keys need separate native wallets and native user concurrency")
	}
	u := f.users[first.ManagedUserID]
	u.Balance -= 1.25
	f.users[u.ID] = u
	k := f.keys[first.ID]
	k.QuotaUsed = 1.25
	f.keys[k.ID] = k
	concurrency, group, status, expiry := 7, int64(2), "inactive", "2031-06-02T01:02:03Z"
	update := UpdateRequest{RequestID: "edit-wallet-0001", Concurrency: &concurrency, GroupID: &group, Status: &status, ExpiresAt: &expiry, BalanceAction: &BalanceAction{Mode: "add", Amount: 2}}
	view, err := m.Update(context.Background(), s, first.ID, update)
	if err != nil {
		t.Fatal(err)
	}
	if view.WalletBalance != 5.75 || view.QuotaUsed != 1.25 || view.Quota != 0 || view.ConcurrencyLimit != 7 || view.Status != "inactive" || view.GroupID == nil || *view.GroupID != 2 {
		t.Fatalf("unexpected edited key: %+v", view)
	}
	if f.users[second.ManagedUserID].Balance != 5 {
		t.Fatal("editing one wallet must not spend the other key's credit")
	}
	if _, err := m.Update(context.Background(), s, first.ID, update); err != nil {
		t.Fatal(err)
	}
	if f.balanceWrites != 1 || f.users[first.ManagedUserID].Balance != 5.75 {
		t.Fatal("same operation was funded twice")
	}
	if _, err := m.Batch(context.Background(), s, request); err != nil {
		t.Fatal(err)
	}
	if f.userCreates != 2 || f.keyCreates != 2 {
		t.Fatal("same batch created additional native resources")
	}
	if f.users[first.ManagedUserID].Balance != 5.75 {
		t.Fatal("batch retry reset a wallet after consumption")
	}
	request.Quota = 99
	if _, err := m.Batch(context.Background(), s, request); err == nil {
		t.Fatal("different batch payload must not reuse an idempotency identifier")
	}
}

func TestManagerRecoversCommittedResourceWithoutDuplicateFunding(t *testing.T) {
	for _, target := range []string{"user", "key"} {
		t.Run(target, func(t *testing.T) {
			m, f, s := newManagerFixture(t)
			f.failUserCommitted = target == "user"
			f.failKeyCommitted = target == "key"
			req := batchInput("batch-recover-0001", 1)
			first, err := m.Batch(context.Background(), s, req)
			if err != nil || first.Failed != 1 {
				t.Fatalf("expected resumable item failure: %+v %v", first, err)
			}
			for id, user := range f.users {
				user.Balance = 4
				f.users[id] = user
			}
			second, err := m.Batch(context.Background(), s, req)
			if err != nil || second.Succeeded != 1 {
				t.Fatalf("resume failed: %+v %v", second, err)
			}
			if f.userCreates != 1 || f.keyCreates != 1 || second.Items[0].Key.WalletBalance != 4 {
				t.Fatal("resource recovery duplicated a user, key, or initial credit")
			}
		})
	}
}

func TestManagerAmbiguousWalletOutcomeNeverReapplies(t *testing.T) {
	m, f, s := newManagerFixture(t)
	key := createOne(t, m, s)
	f.failBalanceCommit = true
	req := UpdateRequest{RequestID: "edit-ambiguous-0001", BalanceAction: &BalanceAction{Mode: "add", Amount: 2}}
	_, err := m.Update(context.Background(), s, key.ID, req)
	if err == nil || strings.Contains(err.Error(), "secret-native") {
		t.Fatal("native errors must be returned safely")
	}
	if f.users[key.ManagedUserID].Balance != 7 || f.balanceWrites != 1 {
		t.Fatal("fixture did not commit before timeout")
	}
	// Restarting the service retains uncertainty and must not send another
	// credit request after the native idempotency retention window expires.
	m = NewManager(m.upstream, m.store, m.master, m.client)
	_, err = m.Update(context.Background(), s, key.ID, req)
	me, ok := err.(*ManagerError)
	if !ok || me.Status != 409 || f.balanceWrites != 1 || f.users[key.ManagedUserID].Balance != 7 {
		t.Fatalf("ambiguous finance write replayed: %v", err)
	}
}

func TestManagerZeroWalletAndStableResolvedAmount(t *testing.T) {
	for _, starting := range []float64{5, 0, -0.25} {
		t.Run(fmt.Sprint(starting), func(t *testing.T) {
			m, f, s := newManagerFixture(t)
			key := createOne(t, m, s)
			user := f.users[key.ManagedUserID]
			user.Balance = starting
			f.users[user.ID] = user
			req := UpdateRequest{RequestID: "edit-clear-0001", BalanceAction: &BalanceAction{Mode: "set", Amount: 0}}
			view, err := m.Update(context.Background(), s, key.ID, req)
			if err != nil || view.WalletBalance != 0 {
				t.Fatalf("clear wallet: %+v %v", view, err)
			}
			if _, err := m.Update(context.Background(), s, key.ID, req); err != nil {
				t.Fatal(err)
			}
			writes := 1
			if starting == 0 {
				writes = 0
			}
			if f.balanceWrites != writes {
				t.Fatal("zeroing a wallet must be atomic and idempotent")
			}
		})
	}
	m, f, s := newManagerFixture(t)
	key := createOne(t, m, s)
	f.balanceRejectOnce = true
	req := UpdateRequest{RequestID: "edit-clear-race-0001", BalanceAction: &BalanceAction{Mode: "set", Amount: 0}}
	if _, err := m.Update(context.Background(), s, key.ID, req); err == nil {
		t.Fatal("concurrent spend should reject stale subtract")
	}
	firstAmount, firstID := f.lastBalance["balance"], f.lastIdempotency
	_, _ = m.Update(context.Background(), s, key.ID, req)
	if f.lastBalance["balance"] != firstAmount || f.lastIdempotency != firstID || f.users[key.ManagedUserID].Balance != 4 {
		t.Fatal("retry changed the resolved amount of a native financial idempotency request")
	}
}

func TestManagerBatchRateLimitRetainsProgress(t *testing.T) {
	m, f, s := newManagerFixture(t)
	f.loginLimit = 1
	req := batchInput("batch-rate-limited-0001", 3)
	first, err := m.Batch(context.Background(), s, req)
	if err != nil || first.Succeeded != 1 || first.Failed != 2 {
		t.Fatalf("partial batch: %+v %v", first, err)
	}
	f.loginLimit = 0
	second, err := m.Batch(context.Background(), s, req)
	if err != nil || second.Succeeded != 3 || second.Failed != 0 || f.userCreates != 3 || f.keyCreates != 3 {
		t.Fatalf("batch resume: %+v %v", second, err)
	}
}

func TestManagerBatchRateLimitAutomaticRetryAndCancellation(t *testing.T) {
	m, f, s := newManagerFixture(t)
	m.batchMaxRetries, m.batchRetryDelay = 5, time.Millisecond
	f.loginLimit, f.loginLimitOnce = 1, true
	result, err := m.Batch(context.Background(), s, batchInput("batch-auto-retry-0001", 3))
	if err != nil || result.Succeeded != 3 || f.userCreates != 3 || f.keyCreates != 3 {
		t.Fatalf("automatic official limiter retry: %+v %v", result, err)
	}

	m2, f2, s2 := newManagerFixture(t)
	m2.batchMaxRetries, m2.batchRetryDelay = 5, time.Minute
	f2.loginLimit = 1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f2.onRateLimit = func() { time.AfterFunc(10*time.Millisecond, cancel) }
	result, err = m2.Batch(ctx, s2, batchInput("batch-cancel-retry-0001", 3))
	if err != nil || result.Succeeded != 1 || result.Failed != 2 || f2.keyCreates != 1 {
		t.Fatalf("cancelled retry lost or duplicated progress: %+v %v", result, err)
	}
	f2.loginLimit, m2.batchMaxRetries = 0, 0
	result, err = m2.Batch(context.Background(), s2, batchInput("batch-cancel-retry-0001", 3))
	if err != nil || result.Succeeded != 3 || f2.keyCreates != 3 || f2.userCreates != 3 {
		t.Fatalf("cancelled batch did not resume: %+v %v", result, err)
	}
}

func TestManagerPaginationAndStoredSecrets(t *testing.T) {
	m, _, s := newManagerFixture(t)
	key := createOne(t, m, s)
	if _, err := m.List(context.Background(), s, SearchRequest{Page: int(^uint(0) >> 1), PageSize: 100, Status: "active"}); err == nil {
		t.Fatal("overflowing page accepted")
	}
	listed, err := m.List(context.Background(), s, SearchRequest{Page: 1, Search: key.Key})
	if err != nil || len(listed.Items) != 1 || listed.Items[0].ID != key.ID {
		t.Fatalf("full key search: %+v %v", listed, err)
	}
	data, err := os.ReadFile(m.store.path)
	if err != nil {
		t.Fatal(err)
	}
	state, err := m.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), key.Key) || strings.Contains(string(data), m.password(state.Records[0])) || strings.Contains(string(data), "owner-") {
		t.Fatal("service state stored a key, native password, or bearer token")
	}
}

func TestManagerRejectsForeignOrChangedNativeIdentity(t *testing.T) {
	m, f, s := newManagerFixture(t)
	key := createOne(t, m, s)
	other := *s
	other.UserID = 2
	req := UpdateRequest{RequestID: "edit-owner-0001", BalanceAction: &BalanceAction{Mode: "add", Amount: 10}}
	if _, err := m.Update(context.Background(), &other, key.ID, req); err == nil {
		t.Fatal("another administrator must not manage this sidecar's user mapping")
	}
	user := f.users[key.ManagedUserID]
	user.Email = "unrelated@example.com"
	f.users[user.ID] = user
	if _, err := m.Update(context.Background(), s, key.ID, req); err == nil {
		t.Fatal("restored/stale mapping must not alter unrelated native users")
	}
	if f.balanceWrites != 0 || f.userWrites != 0 {
		t.Fatal("ownership must be established before any user mutation")
	}
}

func TestManagerGroupAndNameValidationBeforeFunding(t *testing.T) {
	m, f, s := newManagerFixture(t)
	groups, err := m.Groups(context.Background(), s)
	if err != nil || len(groups) != 2 {
		t.Fatalf("only active standard groups: %+v %v", groups, err)
	}
	for i, req := range []BatchRequest{
		{RequestID: "batch-invalid-0001", Count: 1, NamePrefix: "good", GroupID: 3, Quota: 5, Concurrency: 1},
		{RequestID: "batch-invalid-0002", Count: 1, NamePrefix: strings.Repeat("&", 20), GroupID: 1, Quota: 5, Concurrency: 1},
		{RequestID: "batch-invalid-0003", Count: 1, NamePrefix: "good", GroupID: 1, Quota: 5, Concurrency: 0},
	} {
		if _, err := m.Batch(context.Background(), s, req); err == nil {
			t.Fatalf("invalid input %d accepted", i)
		}
	}
	if f.userCreates != 0 || f.balanceWrites != 0 {
		t.Fatal("invalid input created funded native users")
	}
}

func TestManagerPendingBatchRecoveryAndLoginPreflight(t *testing.T) {
	m, f, s := newManagerFixture(t)
	f.backendMode = true
	if _, err := m.Batch(context.Background(), s, batchInput("batch-block-mode-0001", 2)); err == nil {
		t.Fatal("backend mode must stop before funding native users")
	}
	f.backendMode, f.captchaEnabled = false, true
	if _, err := m.Batch(context.Background(), s, batchInput("batch-block-mode-0002", 2)); err == nil {
		t.Fatal("captcha must stop before funding native users")
	}
	if f.userCreates != 0 {
		t.Fatal("login preflight created unusable funded users")
	}
	f.captchaEnabled, f.loginLimit = false, 1
	req := batchInput("batch-page-refresh-0001", 3)
	result, err := m.Batch(context.Background(), s, req)
	if err != nil || result.Succeeded != 1 {
		t.Fatalf("partial setup: %+v %v", result, err)
	}
	// A new manager instance can recover the original UI payload from disk.
	store, err := NewStateStore(m.store.path)
	if err != nil {
		t.Fatal(err)
	}
	m = NewManager(m.upstream, store, m.master, m.client)
	m.batchMaxRetries = 0
	pending, err := m.PendingBatches(context.Background(), s)
	if err != nil || len(pending) != 1 || pending[0].Request != req || pending[0].Ready != 1 || pending[0].Pending != 2 {
		t.Fatalf("pending restore: %+v %v", pending, err)
	}
	other := *s
	other.UserID = 2
	foreign, err := m.PendingBatches(context.Background(), &other)
	if err != nil || len(foreign) != 0 {
		t.Fatal("pending batches leaked across administrators")
	}
	f.loginLimit = 0
	if result, err := m.Batch(context.Background(), s, pending[0].Request); err != nil || result.Succeeded != 3 {
		t.Fatalf("persisted batch resume: %+v %v", result, err)
	}
	pending, err = m.PendingBatches(context.Background(), s)
	if err != nil || len(pending) != 0 {
		t.Fatalf("finished batch still pending: %+v %v", pending, err)
	}
}
