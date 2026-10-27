package web_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/MainAlexStark/email-mcp/internal/httpx"
	"github.com/MainAlexStark/email-mcp/internal/mailboxes"
	"github.com/MainAlexStark/email-mcp/internal/mcp"
	"github.com/MainAlexStark/email-mcp/internal/oauth"
	"github.com/MainAlexStark/email-mcp/internal/pgstore"
	"github.com/MainAlexStark/email-mcp/internal/pgstore/pgtest"
	"github.com/MainAlexStark/email-mcp/internal/secure"
	"github.com/MainAlexStark/email-mcp/internal/tools"
	"github.com/MainAlexStark/email-mcp/internal/web"
	"github.com/MainAlexStark/email-mcp/mail/mailtest"
)

// Сквозные тесты сервиса: настоящая база, настоящие HTTP-обработчики
// кабинета, OAuth и MCP, настоящий IMAP/SMTP в памяти. Собирается так
// же, как в main.

const password = "длинный-пароль-1"

type service struct {
	url  string
	db   *pgstore.DB
	box  *mailtest.Server
	site *web.Web
}

func newService(t *testing.T, reg web.Registration) *service {
	t.Helper()
	db := pgtest.Open(t)
	svc := &service{db: db, box: mailtest.Start(t)}

	key, _ := secure.GenerateSecretKey()
	cipher, err := secure.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	// Почтовый сервер теста живёт на 127.0.0.1 без TLS: запрет
	// внутренних адресов и открытого текста здесь снят, как при
	// MAIL_ALLOW_PRIVATE_HOSTS=true.
	boxSvc := mailboxes.New(db, cipher)
	boxSvc.AllowPlaintext = true

	mux := http.NewServeMux()
	front := httptest.NewServer(mux)
	t.Cleanup(front.Close)
	svc.url = front.URL

	site, err := web.New(db, boxSvc, web.Config{PublicURL: front.URL, Registration: reg})
	if err != nil {
		t.Fatal(err)
	}
	svc.site = site
	o, err := oauth.New(oauth.Config{Issuer: front.URL, Store: db.OAuth(), Accounts: site})
	if err != nil {
		t.Fatal(err)
	}

	apiTokens := func(ctx context.Context, token string) (httpx.Principal, bool) {
		tk, err := db.APITokenByHash(ctx, secure.HashToken(token))
		if err != nil {
			return httpx.Principal{}, false
		}
		return httpx.Principal{UserID: tk.UserID, MailboxID: tk.MailboxID, Grants: httpx.GrantsFromScopes(tk.Scopes)}, true
	}
	usage := func(user, mailbox int64, tool string, failed bool) {
		_ = db.RecordUsage(context.Background(), user, mailbox, tool, failed)
	}

	m := mcp.NewServer("test", "0.0.1")
	tools.RegisterAll(tools.NewRegistry(tools.Config{MailOptions: boxSvc.Options()}, tools.DefaultSafety(), m))

	h, err := httpx.NewServer(m, httpx.Auth{OAuth: o, APITokens: apiTokens}, boxSvc, usage,
		httpx.Config{Safety: tools.DefaultSafety(), Web: site, Ready: db.Ping})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", h.Handler())
	return svc
}

// browser — посетитель со своими cookie; редиректы не следует.
type browser struct {
	t    *testing.T
	base string
	c    *http.Client
}

func (s *service) browser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, base: s.url, c: &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) get(path string) (int, string, string) {
	b.t.Helper()
	resp, err := b.c.Get(b.base + path)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Location"), string(body)
}

func (b *browser) post(path string, form url.Values) (int, string, string) {
	b.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.base)
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Location"), string(body)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (b *browser) csrf() string {
	b.t.Helper()
	_, _, page := b.get("/account")
	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		b.t.Fatalf("на странице нет csrf:\n%s", page)
	}
	return m[1]
}

func (b *browser) signup(email string, extra ...string) {
	b.t.Helper()
	form := url.Values{"email": {email}, "password": {password}, "password2": {password}, "next": {"/account"}}
	if len(extra) > 0 {
		form.Set("invite", extra[0])
	}
	code, loc, body := b.post("/signup", form)
	if code != http.StatusFound || !strings.HasPrefix(loc, "/account/mailboxes/new") {
		b.t.Fatalf("регистрация: %d %s\n%s", code, loc, body)
	}
}

// addMailbox подключает ящик тестового сервера.
func (s *service) addMailbox(b *browser, name, pass string) (int, string, string) {
	b.t.Helper()
	ih, ip, _ := net.SplitHostPort(s.box.IMAPAddr)
	sh, sp, _ := net.SplitHostPort(s.box.SMTPAddr)
	return b.post("/account/mailboxes/new", url.Values{
		"csrf": {b.csrf()}, "name": {name}, "email": {mailtest.User}, "password": {pass},
		"imap_host": {ih}, "imap_port": {ip}, "imap_security": {"none"},
		"smtp_host": {sh}, "smtp_port": {sp}, "smtp_security": {"none"}, "next": {"/account"},
	})
}

var boxIDRe = regexp.MustCompile(`/account/mailboxes/(\d+)/delete`)

func (b *browser) firstMailboxID() string {
	b.t.Helper()
	_, _, page := b.get("/account")
	m := boxIDRe.FindStringSubmatch(page)
	if m == nil {
		b.t.Fatal("в кабинете нет ящика")
	}
	return m[1]
}

// mcpCall вызывает инструмент по HTTP с токеном.
func (s *service) mcpCall(t *testing.T, token, tool string, args map[string]any) (int, string) {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args}})
	req, _ := http.NewRequest(http.MethodPost, s.url+"/mcp", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// oauthConnect проходит подключение Claude целиком и возвращает access-токен.
func (s *service) oauthConnect(t *testing.T, b *browser, mailboxID string, scopes ...string) string {
	t.Helper()
	const redirect = "https://claude.ai/api/mcp/auth_callback"
	reg, _ := json.Marshal(map[string]any{"client_name": "Claude", "redirect_uris": []string{redirect},
		"token_endpoint_auth_method": "none"})
	resp, err := http.Post(s.url+"/oauth/register", "application/json", strings.NewReader(string(reg)))
	if err != nil {
		t.Fatal(err)
	}
	var client struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&client)
	resp.Body.Close()

	verifier := "verifier-0123456789-0123456789-0123456789-abc"
	sum := sha256.Sum256([]byte(verifier))
	authPath := "/oauth/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {client.ClientID}, "redirect_uri": {redirect},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"scope": {"mail:read mail:drafts mail:write mail:send offline_access"}, "state": {"s1"},
	}.Encode()

	code, _, page := b.get(authPath)
	if code != http.StatusOK {
		t.Fatalf("экран согласия: %d\n%s", code, page)
	}
	m := regexp.MustCompile(`name="session" value="([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("нет сессии согласия:\n%s", page)
	}
	form := url.Values{"session": {m[1]}, "action": {"allow"}, "mailbox": {mailboxID}}
	for _, sc := range scopes {
		form.Set("scope_"+sc, "on")
	}
	code, loc, page := b.post("/oauth/authorize", form)
	if code != http.StatusFound {
		t.Fatalf("согласие: %d\n%s", code, page)
	}
	u, _ := url.Parse(loc)
	resp, err = http.PostForm(s.url+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "client_id": {client.ClientID},
		"redirect_uri": {redirect}, "code_verifier": {verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tok map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("токен не выдан: %v", tok)
	}
	return access
}

func isErr(body string) bool { return strings.Contains(body, `"isError":true`) }

// --- тесты ---

func TestFullJourney(t *testing.T) {
	// Путь нового пользователя целиком: регистрация → ящик → подключение
	// Claude → вызов инструмента читает именно его почту.
	s := newService(t, web.RegistrationOpen)
	s.box.Seed(t, "INBOX", mailtest.Message("bob@example.com", mailtest.User, "Добро пожаловать", "Привет!"))
	b := s.browser(t)

	if code, _, page := b.get("/"); code != http.StatusOK || !strings.Contains(page, "Зарегистрироваться") {
		t.Fatalf("главная: %d", code)
	}
	b.signup(pgtest.Email("alex"))

	// Неверный пароль не сохраняется, человек видит понятную причину.
	code, _, page := s.addMailbox(b, "work", "wrong")
	if code != http.StatusBadRequest || !strings.Contains(page, "пароль") {
		t.Fatalf("плохой пароль: %d\n%s", code, page)
	}
	if strings.Contains(page, `value="wrong"`) {
		t.Fatal("введённый пароль вернулся в форму")
	}
	code, loc, page := s.addMailbox(b, "work", mailtest.Password)
	if code != http.StatusFound || loc != "/account?ok=mailbox_added" {
		t.Fatalf("подключение ящика: %d %s\n%s", code, loc, page)
	}
	_, _, page = b.get("/account")
	if !strings.Contains(page, mailtest.User) || strings.Contains(page, mailtest.Password) {
		t.Fatalf("ящик в кабинете показан неверно:\n%s", page)
	}
	boxID := b.firstMailboxID()

	token := s.oauthConnect(t, b, boxID) // только чтение
	code, body := s.mcpCall(t, token, "imap_search_messages", map[string]any{"mailbox": "INBOX"})
	if code != http.StatusOK || isErr(body) || !strings.Contains(body, "Добро пожаловать") {
		t.Fatalf("поиск: %d %s", code, body)
	}

	// Подключение без права отправки не отправляет.
	_, body = s.mcpCall(t, token, "smtp_send_message", map[string]any{"to": []string{"x@y.ru"}, "subject": "s", "body_text": "b"})
	if !isErr(body) || len(s.box.SentMessages()) != 0 {
		t.Fatalf("отправка без права: %s", body)
	}

	_, _, page = b.get("/account")
	if !strings.Contains(page, "вызовов за 30 дней: 2") {
		t.Errorf("учёт вызовов не виден в кабинете")
	}
	if !strings.Contains(page, "Claude") || !strings.Contains(page, "Отозвать") {
		t.Errorf("подключение не видно в кабинете")
	}

	// Удаление ящика обрывает подключение к нему сразу.
	code, _, _ = b.post("/account/mailboxes/"+boxID+"/delete", url.Values{"csrf": {b.csrf()}})
	if code != http.StatusFound {
		t.Fatalf("удаление ящика: %d", code)
	}
	if code, _ := s.mcpCall(t, token, "imap_list_mailboxes", nil); code == http.StatusOK {
		t.Fatal("подключение к удалённому ящику продолжает работать")
	}
}

func TestAllMailboxesConnectionAndSend(t *testing.T) {
	s := newService(t, web.RegistrationOpen)
	b := s.browser(t)
	b.signup(pgtest.Email("all"))
	s.addMailbox(b, "work", mailtest.Password)
	s.addMailbox(b, "home", mailtest.Password)

	token := s.oauthConnect(t, b, "0", "send")
	_, body := s.mcpCall(t, token, "list_all_accounts", nil)
	if !strings.Contains(body, `\"work\"`) || !strings.Contains(body, `\"home\"`) {
		t.Fatalf("подключение ко всем ящикам видит не всё: %s", body)
	}
	_, body = s.mcpCall(t, token, "smtp_send_message", map[string]any{"account_id": "home",
		"to": []string{"bob@example.com"}, "subject": "Привет", "body_text": "Тест"})
	if isErr(body) || len(s.box.SentMessages()) != 1 {
		t.Fatalf("отправка с правом: %s", body)
	}
	// Ящик, добавленный после подключения, виден сразу.
	s.addMailbox(b, "later", mailtest.Password)
	if _, body := s.mcpCall(t, token, "list_all_accounts", nil); !strings.Contains(body, `\"later\"`) {
		t.Fatalf("новый ящик не виден подключению ко всем: %s", body)
	}
}

func TestInviteRegistration(t *testing.T) {
	s := newService(t, web.RegistrationInvite)
	b := s.browser(t)
	code, _, page := b.get("/signup?invite=abc")
	if code != http.StatusOK || !strings.Contains(page, `name="invite" value="abc"`) {
		t.Fatalf("форма с кодом из ссылки: %d", code)
	}
	// Без кода и с выдуманным кодом — отказ.
	if code, _, page := b.post("/signup", url.Values{"email": {pgtest.Email("x")}, "password": {password}, "password2": {password}}); code != http.StatusBadRequest || !strings.Contains(page, "приглашени") {
		t.Fatalf("регистрация без кода: %d", code)
	}
	if code, _, _ := b.post("/signup", url.Values{"email": {pgtest.Email("x")}, "password": {password}, "password2": {password}, "invite": {"выдумка"}}); code != http.StatusBadRequest {
		t.Fatalf("выдуманный код: %d", code)
	}
	invite, _ := secure.RandomToken()
	if _, err := s.db.CreateInvite(context.Background(), secure.HashToken(invite), "тест", nil); err != nil {
		t.Fatal(err)
	}
	b.signup(pgtest.Email("invited"), invite)
	// Второй раз тот же код не работает.
	b2 := s.browser(t)
	if code, _, _ := b2.post("/signup", url.Values{"email": {pgtest.Email("y")}, "password": {password}, "password2": {password}, "invite": {invite}}); code != http.StatusBadRequest {
		t.Fatalf("повторное приглашение: %d", code)
	}
}

func TestClosedRegistration(t *testing.T) {
	s := newService(t, web.RegistrationClosed)
	b := s.browser(t)
	if code, _, _ := b.get("/signup"); code != http.StatusForbidden {
		t.Fatalf("закрытая регистрация отдаёт форму: %d", code)
	}
	if _, _, page := b.get("/"); strings.Contains(page, "Зарегистрироваться") {
		t.Fatal("на главной ссылка на закрытую регистрацию")
	}
}

func TestPlaintextRefusedByDefault(t *testing.T) {
	db := pgtest.Open(t)
	key, _ := secure.GenerateSecretKey()
	cipher, _ := secure.NewCipher(key)
	svc := mailboxes.New(db, cipher)
	u, _ := db.CreateUser(context.Background(), pgtest.Email("plain"), "h")
	_, err := svc.Connect(context.Background(), u.ID, mailboxes.Form{Email: "a@example.com", Password: "p",
		IMAPHost: "imap.example.com", IMAPSecurity: "none"})
	if err == nil || !strings.Contains(err.Error(), "без шифрования") {
		t.Fatalf("ящик без TLS должен отклоняться: %v", err)
	}
}

func TestAnonymousOAuthGoesThroughLoginAndBack(t *testing.T) {
	s := newService(t, web.RegistrationOpen)
	b := s.browser(t)
	email := pgtest.Email("oauth")
	b.signup(email)
	b.post("/logout", url.Values{"csrf": {b.csrf()}})

	next := "/oauth/authorize?client_id=x&response_type=code"
	code, loc, _ := b.post("/login", url.Values{"email": {email}, "password": {password}, "next": {next}})
	if code != http.StatusFound || loc != next {
		t.Fatalf("после входа не вернулись к согласию: %d %s", code, loc)
	}
}

func TestLoginRejectsWrongPasswordAndOpenRedirect(t *testing.T) {
	s := newService(t, web.RegistrationOpen)
	b := s.browser(t)
	email := pgtest.Email("login")
	b.signup(email)
	b.post("/logout", url.Values{"csrf": {b.csrf()}})

	if code, _, page := b.post("/login", url.Values{"email": {email}, "password": {"не-тот-пароль"}}); code != http.StatusUnauthorized || !strings.Contains(page, "Неверная почта или пароль") {
		t.Fatalf("неверный пароль: %d", code)
	}
	if _, _, page := b.post("/login", url.Values{"email": {"nobody@example.com"}, "password": {"x"}}); !strings.Contains(page, "Неверная почта или пароль") {
		t.Fatal("для неизвестного адреса другой ответ")
	}
	for _, evil := range []string{"//evil.example", "https://evil.example", "/\\evil.example"} {
		code, loc, _ := b.post("/login", url.Values{"email": {email}, "password": {password}, "next": {evil}})
		if code != http.StatusFound || loc != "/account" {
			t.Fatalf("открытый редирект через next=%q: %d %s", evil, code, loc)
		}
	}
}

func TestCSRFAndForeignOriginRejected(t *testing.T) {
	s := newService(t, web.RegistrationOpen)
	b := s.browser(t)
	b.signup(pgtest.Email("csrf"))

	if code, _, _ := b.post("/account/tokens", url.Values{"name": {"x"}}); code != http.StatusForbidden {
		t.Fatalf("форма без csrf прошла: %d", code)
	}
	req, _ := http.NewRequest(http.MethodPost, s.url+"/login", strings.NewReader("email=a&password=b"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("вход с чужого Origin: %d", resp.StatusCode)
	}
}

func TestUsersCannotTouchEachOthersMailboxes(t *testing.T) {
	s := newService(t, web.RegistrationOpen)
	alice := s.browser(t)
	alice.signup(pgtest.Email("alice"))
	s.addMailbox(alice, "alice", mailtest.Password)
	aliceBox := alice.firstMailboxID()

	bob := s.browser(t)
	bob.signup(pgtest.Email("bob"))
	for _, action := range []string{"delete", "check", "edit"} {
		code, _, _ := bob.post("/account/mailboxes/"+aliceBox+"/"+action, url.Values{"csrf": {bob.csrf()}, "email": {"x@y.z"}})
		if code != http.StatusNotFound {
			t.Fatalf("чужой ящик, действие %s: %d", action, code)
		}
	}
	if code, _, _ := bob.get("/account/mailboxes/" + aliceBox + "/edit"); code != http.StatusNotFound {
		t.Fatalf("форма чужого ящика: %d", code)
	}
	_, _, page := bob.post("/account/tokens", url.Values{"csrf": {bob.csrf()}, "mailbox": {aliceBox}, "name": {"x"}})
	if strings.Contains(page, httpx.APITokenPrefix) {
		t.Fatal("выпущен токен к чужому ящику")
	}
	if strings.Contains(page, "alice") {
		t.Fatal("в кабинете Боба виден ящик Алисы")
	}
}

var tokenRe = regexp.MustCompile(`emc_[A-Za-z0-9_-]{20,}`)

func TestAPITokenLifecycle(t *testing.T) {
	s := newService(t, web.RegistrationOpen)
	b := s.browser(t)
	b.signup(pgtest.Email("api"))
	s.addMailbox(b, "work", mailtest.Password)

	_, _, page := b.post("/account/tokens", url.Values{"csrf": {b.csrf()}, "mailbox": {"0"}, "name": {"Отчёты"}, "drafts": {"on"}})
	token := tokenRe.FindString(page)
	if token == "" {
		t.Fatalf("токен не показан:\n%s", page)
	}
	if code, body := s.mcpCall(t, token, "draft_create", map[string]any{"to": []string{"b@x.ru"}, "subject": "s", "body_text": "b"}); code != http.StatusOK || isErr(body) {
		t.Fatalf("черновик по API-токену: %d %s", code, body)
	}
	if _, body := s.mcpCall(t, token, "imap_create_mailbox", map[string]any{"mailbox_name": "x"}); !isErr(body) {
		t.Fatal("токен без права изменения меняет ящик")
	}
	if _, _, page := b.get("/account"); strings.Contains(page, token) {
		t.Fatal("токен виден повторно")
	}
	_, _, page = b.get("/account")
	id := regexp.MustCompile(`/account/tokens/(\d+)/delete`).FindStringSubmatch(page)
	if id == nil {
		t.Fatal("нет кнопки отзыва")
	}
	b.post("/account/tokens/"+id[1]+"/delete", url.Values{"csrf": {b.csrf()}})
	if code, _ := s.mcpCall(t, token, "imap_list_mailboxes", nil); code != http.StatusUnauthorized {
		t.Fatalf("отозванный токен: %d", code)
	}
}

func TestMailboxEditKeepsPasswordWhenEmpty(t *testing.T) {
	s := newService(t, web.RegistrationOpen)
	b := s.browser(t)
	b.signup(pgtest.Email("edit"))
	s.addMailbox(b, "work", mailtest.Password)
	id := b.firstMailboxID()

	code, _, page := b.get("/account/mailboxes/" + id + "/edit")
	if code != http.StatusOK || strings.Contains(page, mailtest.Password) {
		t.Fatalf("форма правки: %d", code)
	}
	ih, ip, _ := net.SplitHostPort(s.box.IMAPAddr)
	code, loc, page := b.post("/account/mailboxes/"+id+"/edit", url.Values{"csrf": {b.csrf()},
		"email": {mailtest.User}, "display_name": {"Алекс"}, "imap_host": {ih}, "imap_port": {ip},
		"imap_security": {"none"}, "password": {""}})
	if code != http.StatusFound || loc != "/account?ok=mailbox_saved" {
		t.Fatalf("правка без пароля: %d %s\n%s", code, loc, page)
	}
	m, _ := s.db.Mailboxes(context.Background(), mustUserID(t, s, b))
	if len(m) != 1 || m[0].DisplayName != "Алекс" || m[0].SMTPHost != "" {
		t.Fatalf("после правки: %+v", m)
	}
}

func mustUserID(t *testing.T, s *service, b *browser) int64 {
	t.Helper()
	_, _, page := b.get("/account")
	m := regexp.MustCompile(`([a-z]+-[0-9a-f]{12}@example\.com) · тариф`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("нет адреса в кабинете")
	}
	u, err := s.db.UserByEmail(context.Background(), m[1])
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestAccountDeletion(t *testing.T) {
	s := newService(t, web.RegistrationOpen)
	b := s.browser(t)
	email := pgtest.Email("gone")
	b.signup(email)
	s.addMailbox(b, "work", mailtest.Password)
	token := s.oauthConnect(t, b, b.firstMailboxID(), "write")

	if code, _, _ := b.post("/account/delete", url.Values{"csrf": {b.csrf()}, "password": {"не-тот"}}); code != http.StatusBadRequest {
		t.Fatalf("удаление с неверным паролем: %d", code)
	}
	if code, _, _ := b.post("/account/delete", url.Values{"csrf": {b.csrf()}, "password": {password}}); code != http.StatusOK {
		t.Fatalf("удаление: %d", code)
	}
	if _, err := s.db.UserByEmail(context.Background(), email); err == nil {
		t.Fatal("пользователь остался в базе")
	}
	if code, _ := s.mcpCall(t, token, "imap_list_mailboxes", nil); code == http.StatusOK {
		t.Fatal("подключение удалённого пользователя работает")
	}
}

func TestHealthChecksDatabase(t *testing.T) {
	s := newService(t, web.RegistrationOpen)
	resp, err := http.Get(s.url + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %d", resp.StatusCode)
	}
}
