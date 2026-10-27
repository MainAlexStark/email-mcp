package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MainAlexStark/email-mcp/internal/mcp"
	"github.com/MainAlexStark/email-mcp/internal/oauth"
	"github.com/MainAlexStark/email-mcp/internal/secure"
	"github.com/MainAlexStark/email-mcp/internal/tools"
	"github.com/MainAlexStark/email-mcp/mail"
	"github.com/MainAlexStark/email-mcp/mail/mailtest"
)

const (
	readToken = "emc_read0000000000000000000000000000000000000000000"
	sendToken = "emc_send0000000000000000000000000000000000000000000"
	// otherToken — токен второго пользователя ко всем его ящикам.
	otherToken = "emc_other000000000000000000000000000000000000000000"
)

// fakeMailboxes — ящики теста: (пользователь, номер) → ящик на своём
// почтовом сервере в памяти.
type fakeMailboxes struct {
	boxes map[[2]int64]mail.Account
}

func (f *fakeMailboxes) Accounts(_ context.Context, userID, mailboxID int64) ([]mail.Account, error) {
	if mailboxID > 0 {
		acc, ok := f.boxes[[2]int64{userID, mailboxID}]
		if !ok {
			return nil, errors.New("нет такого ящика")
		}
		return []mail.Account{acc}, nil
	}
	var out []mail.Account
	for _, id := range []int64{10, 11, 20} {
		if acc, ok := f.boxes[[2]int64{userID, id}]; ok {
			out = append(out, acc)
		}
	}
	return out, nil
}

type usageRecord struct {
	user, mailbox int64
	tool          string
	failed        bool
}

// harness — сетевой MCP поверх настоящих почтовых серверов в памяти:
// пользователь 1 с ящиками 10 (work) и 11 (home), пользователь 2 с
// ящиком 20 (other).
type harness struct {
	front *httptest.Server
	oauth *oauth.Server
	store *oauth.MemoryStore
	mine  *mailtest.Server
	other *mailtest.Server

	mu    sync.Mutex
	usage []usageRecord
}

func (h *harness) records() []usageRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]usageRecord(nil), h.usage...)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{store: oauth.NewMemoryStore(), mine: mailtest.Start(t), other: mailtest.Start(t)}
	boxes := &fakeMailboxes{boxes: map[[2]int64]mail.Account{
		{1, 10}: h.mine.Account("work"),
		{1, 11}: h.mine.Account("home"),
		{2, 20}: h.other.Account("other"),
	}}

	// В сервисном режиме у реестра нет своих ящиков: они приходят
	// только из запроса.
	m := mcp.NewServer("test", "0.0.1")
	tools.RegisterAll(tools.NewRegistry(tools.Config{}, tools.DefaultSafety(), m))

	apiTokens := func(_ context.Context, token string) (Principal, bool) {
		switch token {
		case readToken:
			return Principal{UserID: 1, MailboxID: 10}, true
		case sendToken:
			return Principal{UserID: 1, MailboxID: 10, Grants: Grants{Send: true}}, true
		case otherToken:
			return Principal{UserID: 2}, true
		}
		return Principal{}, false
	}

	mux := http.NewServeMux()
	front := httptest.NewServer(mux)
	t.Cleanup(front.Close)

	o, err := oauth.New(oauth.Config{Issuer: front.URL, Store: h.store, Accounts: noAccounts{}})
	if err != nil {
		t.Fatal(err)
	}
	h.oauth = o

	usage := func(user, mailbox int64, tool string, failed bool) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.usage = append(h.usage, usageRecord{user, mailbox, tool, failed})
	}

	// Права процесса нарочно открыты полностью: сервис обязан брать
	// права из токена, а не из настроек процесса.
	procSafety := tools.DefaultSafety()
	procSafety.Drafts, procSafety.Write, procSafety.Send = true, true, true
	s, err := NewServer(m, Auth{OAuth: o, APITokens: apiTokens}, boxes, usage, Config{Safety: procSafety})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", s.Handler())
	h.front = front
	return h
}

// issueOAuth кладёт в хранилище действующий OAuth-токен.
func (h *harness) issueOAuth(t *testing.T, userID, mailboxID int64, scopes ...string) string {
	t.Helper()
	token := "oauth-" + strings.Repeat("t", 40) + fmt.Sprint(userID, mailboxID, len(scopes))
	err := h.store.SaveTokens(context.Background(), &oauth.Token{
		TokenHash: secure.HashToken(token),
		ClientID:  "claude",
		Scopes:    scopes,
		Resource:  h.oauth.ResourceURL(),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		GrantID:   "g-" + token,
		Subject:   oauth.Subject{UserID: userID, MailboxID: mailboxID},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type noAccounts struct{}

func (noAccounts) CurrentUser(*http.Request) (oauth.User, bool)              { return oauth.User{}, false }
func (noAccounts) Mailboxes(context.Context, int64) ([]oauth.Mailbox, error) { return nil, nil }
func (noAccounts) LoginURL(string) string                                    { return "/login" }
func (noAccounts) AddMailboxURL(string) string                               { return "/account" }

// rpc отправляет JSON-RPC сообщение по HTTP.
func rpc(t *testing.T, base, path, token, method string, params any) (*http.Response, string) {
	t.Helper()

	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		body["params"] = params
	}
	raw, _ := json.Marshal(body)

	url := base + path
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	raw2, _ := io.ReadAll(resp.Body)
	return resp, string(raw2)
}

// toolCall — параметры вызова инструмента.
func toolCall(name string, args any) map[string]any {
	return map[string]any{"name": name, "arguments": args}
}

// isToolError разбирает ответ и говорит, вернул ли инструмент ошибку.
func isToolError(t *testing.T, body string) (bool, string) {
	t.Helper()

	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("ответ не разобрался: %v\n%s", err, body)
	}
	text := ""
	if len(resp.Result.Content) > 0 {
		text = resp.Result.Content[0].Text
	}
	return resp.Result.IsError, text
}

func TestNoTokenRejected(t *testing.T) {
	front := newHarness(t).front

	resp, _ := rpc(t, front.URL, "/mcp", "", "tools/list", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("без токена ожидался 401, получен %d", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("на 401 должен возвращаться WWW-Authenticate")
	}
}

func TestWrongTokenRejected(t *testing.T) {
	front := newHarness(t).front

	resp, _ := rpc(t, front.URL, "/mcp", strings.Repeat("x", 64), "tools/list", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("с чужим токеном ожидался 401, получен %d", resp.StatusCode)
	}
}

func TestTokenInPathRejected(t *testing.T) {
	// Раньше так подключался телефон. Спецификация MCP это запрещает:
	// адрес с токеном оседает в журналах прокси и истории браузера.
	// Теперь для телефона есть OAuth, а этот путь закрыт.
	front := newHarness(t).front

	resp, _ := rpc(t, front.URL, "/mcp/"+readToken, "", "tools/list", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("токен в адресе больше не должен приниматься, получен %d", resp.StatusCode)
	}
}

func TestForeignOriginRejected(t *testing.T) {
	// Защита от DNS rebinding: сайт в браузере не должен ходить
	// к серверу от имени пользователя.
	front := newHarness(t).front

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+readToken)
	req.Header.Set("Origin", "https://evil.example")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("чужой Origin должен отклоняться, получен %d", resp.StatusCode)
	}
}

func TestNotificationGets202(t *testing.T) {
	front := newHarness(t).front

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	req.Header.Set("Authorization", "Bearer "+readToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("на уведомление ожидался 202, получен %d", resp.StatusCode)
	}
}

func TestAcceptMustNameBothFormats(t *testing.T) {
	// Спецификация требует от клиента готовности принять оба формата.
	// Прежняя реализация была снисходительнее и отвечала потоком
	// событий тому, кто просил только его; SDK такие запросы отклоняет.
	// Для автоматизации это значит: заголовки обязательны — см.
	// docs/REMOTE.md.
	front := newHarness(t).front

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+readToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("неполный Accept должен отклоняться, получен %d", resp.StatusCode)
	}
}

func TestHostFromReverseProxyIsAccepted(t *testing.T) {
	// Штатная схема развёртывания: Caddy на 443 и сервер на localhost.
	// Запрос приходит на петлевой адрес с внешним Host — встроенная
	// в SDK защита от DNS rebinding отклонила бы его, и сервер за
	// прокси перестал бы работать целиком.
	front := newHarness(t).front

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+readToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Host = "mail-mcp.example.com"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("запрос из-за обратного прокси должен проходить, получен %d: %s", resp.StatusCode, body)
	}
}

func TestGetIsNotAllowed(t *testing.T) {
	front := newHarness(t).front

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+readToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET должен отвечать 405, получен %d", resp.StatusCode)
	}
}

func TestHealthNeedsNoToken(t *testing.T) {
	front := newHarness(t).front

	resp, err := http.Get(front.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz должен отвечать без токена, получен %d", resp.StatusCode)
	}
}

func sendArgs() map[string]any {
	return map[string]any{"to": []string{"bob@example.com"}, "subject": "Привет", "body_text": "Тест"}
}

func TestReadTokenCannotSend(t *testing.T) {
	h := newHarness(t)
	_, body := rpc(t, h.front.URL, "/mcp", readToken, "tools/call", toolCall("smtp_send_message", sendArgs()))
	isErr, text := isToolError(t, body)
	if !isErr || !strings.Contains(text, "Отправка") {
		t.Fatalf("токен без права отправки должен получать отказ: %s", text)
	}
	if len(h.mine.SentMessages()) != 0 {
		t.Fatal("письмо ушло по токену без права отправки")
	}
}

func TestSendTokenCanSend(t *testing.T) {
	h := newHarness(t)
	_, body := rpc(t, h.front.URL, "/mcp", sendToken, "tools/call", toolCall("smtp_send_message", sendArgs()))
	if isErr, text := isToolError(t, body); isErr {
		t.Fatalf("отправка по токену с правом: %s", text)
	}
	if len(h.mine.SentMessages()) != 1 {
		t.Fatal("письмо не ушло")
	}
	// Право отправки не даёт права менять ящик.
	_, body = rpc(t, h.front.URL, "/mcp", sendToken, "tools/call",
		toolCall("imap_create_mailbox", map[string]any{"mailbox_name": "x"}))
	if isErr, _ := isToolError(t, body); !isErr {
		t.Fatal("право отправки не должно открывать изменение ящика")
	}
}

func TestStatusReportsGrantsOfConnection(t *testing.T) {
	h := newHarness(t)
	_, readBody := rpc(t, h.front.URL, "/mcp", readToken, "tools/call", toolCall("mail_status", map[string]any{}))
	if _, text := isToolError(t, readBody); !strings.Contains(text, "Права этого подключения:  чтение\n") {
		t.Errorf("статус читающего токена: %s", text)
	}
	_, sendBody := rpc(t, h.front.URL, "/mcp", sendToken, "tools/call", toolCall("mail_status", map[string]any{}))
	if _, text := isToolError(t, sendBody); !strings.Contains(text, "чтение + отправка") {
		t.Errorf("статус токена с отправкой: %s", text)
	}
}

func accountIDsOf(t *testing.T, body string) []string {
	t.Helper()
	isErr, text := isToolError(t, body)
	if isErr {
		t.Fatalf("list_all_accounts: %s", text)
	}
	var out struct {
		Accounts []struct {
			AccountID string `json:"account_id"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	var ids []string
	for _, a := range out.Accounts {
		ids = append(ids, a.AccountID)
	}
	return ids
}

func TestOAuthTokenSeesOnlyItsMailboxes(t *testing.T) {
	// Главное свойство сервиса: запрос видит ровно те ящики, к которым
	// выдан токен, — один выбранный или все ящики своего владельца.
	h := newHarness(t)

	one := h.issueOAuth(t, 1, 10, oauth.ScopeRead)
	_, body := rpc(t, h.front.URL, "/mcp", one, "tools/call", toolCall("list_all_accounts", map[string]any{}))
	if ids := accountIDsOf(t, body); len(ids) != 1 || ids[0] != "work" {
		t.Fatalf("токен к одному ящику видит: %v", ids)
	}
	_, body = rpc(t, h.front.URL, "/mcp", one, "tools/call",
		toolCall("imap_list_mailboxes", map[string]any{"account_id": "home"}))
	if isErr, _ := isToolError(t, body); !isErr {
		t.Fatal("токен к ящику work не должен открывать ящик home")
	}

	all := h.issueOAuth(t, 1, 0, oauth.ScopeRead)
	_, body = rpc(t, h.front.URL, "/mcp", all, "tools/call", toolCall("list_all_accounts", map[string]any{}))
	if ids := accountIDsOf(t, body); len(ids) != 2 {
		t.Fatalf("токен ко всем ящикам видит: %v", ids)
	}
}

func TestOtherUsersTokenSeesOnlyTheirMailboxes(t *testing.T) {
	h := newHarness(t)
	_, body := rpc(t, h.front.URL, "/mcp", otherToken, "tools/call", toolCall("list_all_accounts", map[string]any{}))
	if ids := accountIDsOf(t, body); len(ids) != 1 || ids[0] != "other" {
		t.Fatalf("второй пользователь видит: %v", ids)
	}
	_, body = rpc(t, h.front.URL, "/mcp", otherToken, "tools/call",
		toolCall("imap_list_mailboxes", map[string]any{"account_id": "work"}))
	if isErr, _ := isToolError(t, body); !isErr {
		t.Fatal("чужой ящик открылся")
	}
	if h.mine.Logins() != 0 {
		t.Fatal("запрос второго пользователя дошёл до почтового сервера первого")
	}
}

func TestOAuthScopesBecomeGrants(t *testing.T) {
	h := newHarness(t)
	token := h.issueOAuth(t, 1, 10, oauth.ScopeRead, oauth.ScopeDrafts)
	_, body := rpc(t, h.front.URL, "/mcp", token, "tools/call", toolCall("smtp_send_message", sendArgs()))
	if isErr, _ := isToolError(t, body); !isErr {
		t.Fatal("OAuth-токен без mail:send не должен отправлять")
	}
	_, body = rpc(t, h.front.URL, "/mcp", token, "tools/call", toolCall("draft_create", sendArgs()))
	if isErr, text := isToolError(t, body); isErr {
		t.Fatalf("с mail:drafts черновик должен создаваться: %s", text)
	}
	if len(h.mine.SentMessages()) != 0 {
		t.Fatal("письмо ушло без права отправки")
	}
}

func TestDeletedMailboxGets403NotLoop(t *testing.T) {
	// Токен жив, а ящика нет. 401 здесь заставил бы Claude бесконечно
	// обновлять токен.
	h := newHarness(t)
	token := h.issueOAuth(t, 1, 99, oauth.ScopeRead)
	resp, _ := rpc(t, h.front.URL, "/mcp", token, "tools/list", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("к удалённому ящику ожидался 403, получен %d", resp.StatusCode)
	}
}

func TestUsageIsRecordedPerMailbox(t *testing.T) {
	h := newHarness(t)
	rpc(t, h.front.URL, "/mcp", readToken, "tools/call", toolCall("imap_list_mailboxes", map[string]any{}))
	rpc(t, h.front.URL, "/mcp", readToken, "tools/call", toolCall("smtp_send_message", sendArgs()))
	rpc(t, h.front.URL, "/mcp", readToken, "tools/list", nil)

	got := h.records()
	if len(got) != 2 {
		t.Fatalf("учтено %d вызовов, ожидалось 2 (tools/list не вызов инструмента): %+v", len(got), got)
	}
	if got[0] != (usageRecord{1, 10, "imap_list_mailboxes", false}) {
		t.Errorf("первый вызов: %+v", got[0])
	}
	if got[1] != (usageRecord{1, 10, "smtp_send_message", true}) {
		t.Errorf("отказ должен учитываться как ошибка: %+v", got[1])
	}
}

func TestRootIsNotMCP(t *testing.T) {
	// MCP живёт только на /mcp; корень — страницы сервиса.
	h := newHarness(t)
	resp, _ := rpc(t, h.front.URL, "/", readToken, "tools/list", nil)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("корень не должен обслуживать MCP")
	}
}
