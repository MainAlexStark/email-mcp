package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeAccounts — пользователи и ящики для тестов. Вошедший
// пользователь определяется cookie uid.
type fakeAccounts struct {
	users map[string]User
	boxes map[int64][]Mailbox
}

func (f *fakeAccounts) CurrentUser(r *http.Request) (User, bool) {
	c, err := r.Cookie("uid")
	if err != nil {
		return User{}, false
	}
	u, ok := f.users[c.Value]
	return u, ok
}

func (f *fakeAccounts) Mailboxes(_ context.Context, userID int64) ([]Mailbox, error) {
	return f.boxes[userID], nil
}

func (f *fakeAccounts) LoginURL(next string) string { return "/login?next=" + url.QueryEscape(next) }
func (f *fakeAccounts) AddMailboxURL(next string) string {
	return "/account/mailboxes/new?next=" + url.QueryEscape(next)
}

// harness — сервер авторизации на настоящем HTTP.
type harness struct {
	srv      *httptest.Server
	oauth    *Server
	client   *http.Client
	accounts *fakeAccounts
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	mux := http.NewServeMux()
	httpSrv := httptest.NewServer(mux)
	t.Cleanup(httpSrv.Close)

	accounts := &fakeAccounts{
		users: map[string]User{
			"1": {ID: 1, Email: "alex@example.com"},
			"2": {ID: 2, Email: "other@example.com"},
			"3": {ID: 3, Email: "nomail@example.com"},
		},
		boxes: map[int64][]Mailbox{
			1: {{ID: 10, Name: "work", Email: "alex@work.example"}, {ID: 11, Name: "home", Email: "alex@home.example"}},
			2: {{ID: 20, Name: "foreign", Email: "other@foreign.example"}},
		},
	}

	o, err := New(Config{
		Issuer:      httpSrv.URL,
		ResourceURL: httpSrv.URL + "/mcp",
		Store:       NewMemoryStore(),
		Accounts:    accounts,
	})
	if err != nil {
		t.Fatal(err)
	}
	o.Mount(mux)

	jar, _ := cookiejar.New(nil)
	// Редиректы не следуем: нам нужно прочитать сам Location.
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	h := &harness{srv: httpSrv, oauth: o, client: client, accounts: accounts}
	h.loginAs("1")
	return h
}

// loginAs подменяет вошедшего пользователя ("" — выйти).
func (h *harness) loginAs(uid string) {
	u, _ := url.Parse(h.srv.URL)
	c := &http.Cookie{Name: "uid", Value: uid, Path: "/"}
	if uid == "" {
		c.MaxAge = -1
	}
	h.client.Jar.SetCookies(u, []*http.Cookie{c})
}

func (h *harness) getJSON(t *testing.T, path string) map[string]any {
	t.Helper()

	resp, err := h.client.Get(h.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: статус %d", path, resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return out
}

// register регистрирует клиента через DCR.
func (h *harness) register(t *testing.T, redirectURI string) string {
	t.Helper()

	body, _ := json.Marshal(map[string]any{
		"client_name":                "Claude (тест)",
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "none",
	})

	resp, err := h.client.Post(h.srv.URL+"/oauth/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("регистрация: статус %d, тело %s", resp.StatusCode, raw)
	}

	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.ClientID == "" {
		t.Fatal("не выдан client_id")
	}
	return out.ClientID
}

// pkce возвращает пару verifier/challenge.
func pkce(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// consent проходит экран согласия и возвращает код авторизации.
func (h *harness) consent(t *testing.T, clientID, redirectURI, challenge, scope string, allowWrite bool) (code string, status int) {
	t.Helper()

	authURL := h.srv.URL + "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {scope},
		"state":                 {"состояние-123"},
		"resource":              {h.oauth.ResourceURL()},
	}.Encode()

	resp, err := h.client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode
	}

	sessionID := extractSession(t, string(page))

	form := url.Values{
		"session":    {sessionID},
		"action":     {"allow"},
		"mailbox":    {"10"},
		"scope_read": {"on"},
	}
	if allowWrite {
		form.Set("scope_write", "on")
	}

	resp2, err := h.client.PostForm(h.srv.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusFound {
		raw, _ := io.ReadAll(resp2.Body)
		t.Fatalf("подтверждение: статус %d, тело %s", resp2.StatusCode, raw)
	}

	loc, err := url.Parse(resp2.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if e := loc.Query().Get("error"); e != "" {
		t.Fatalf("вернулась ошибка: %s (%s)", e, loc.Query().Get("error_description"))
	}
	if got := loc.Query().Get("state"); got != "состояние-123" {
		t.Errorf("state не вернулся: %q", got)
	}
	if got := loc.Query().Get("iss"); got != h.oauth.Issuer() {
		t.Errorf("iss не вернулся или неверен: %q", got)
	}
	return loc.Query().Get("code"), resp2.StatusCode
}

func extractSession(t *testing.T, page string) string {
	t.Helper()

	const marker = `name="session" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("на странице согласия нет идентификатора сессии:\n%s", page)
	}
	rest := page[i+len(marker):]
	j := strings.Index(rest, `"`)
	return rest[:j]
}

// exchange меняет код на токены.
func (h *harness) exchange(t *testing.T, clientID, code, verifier, redirectURI string) map[string]any {
	t.Helper()

	resp, err := h.client.PostForm(h.srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
		"resource":      {h.oauth.ResourceURL()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("обмен кода: статус %d, тело %v", resp.StatusCode, out)
	}
	return out
}

// --- Тесты ---

func TestDiscoveryDocuments(t *testing.T) {
	h := newHarness(t)

	prm := h.getJSON(t, "/.well-known/oauth-protected-resource")
	if prm["resource"] != h.oauth.ResourceURL() {
		t.Errorf("resource = %v, want %v", prm["resource"], h.oauth.ResourceURL())
	}
	servers, _ := prm["authorization_servers"].([]any)
	if len(servers) == 0 || servers[0] != h.oauth.Issuer() {
		t.Errorf("authorization_servers = %v", prm["authorization_servers"])
	}

	asm := h.getJSON(t, "/.well-known/oauth-authorization-server")
	if asm["issuer"] != h.oauth.Issuer() {
		t.Errorf("issuer = %v", asm["issuer"])
	}
	// Без объявленного S256 совместимый клиент не начнёт поток.
	methods, _ := asm["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v", asm["code_challenge_methods_supported"])
	}
	if asm["registration_endpoint"] == nil {
		t.Error("нет registration_endpoint: Claude не сможет зарегистрироваться через DCR")
	}
}

func TestDiscoveryWorksUnderResourcePathSuffix(t *testing.T) {
	// Claude сначала пробует путь с суффиксом ресурса и лишь потом
	// корневой. Отвечать надо на оба.
	h := newHarness(t)

	prm := h.getJSON(t, "/.well-known/oauth-protected-resource/mcp")
	if prm["resource"] != h.oauth.ResourceURL() {
		t.Errorf("resource = %v", prm["resource"])
	}
}

func TestFullAuthorizationCodeFlow(t *testing.T) {
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"

	clientID := h.register(t, redirectURI)

	verifier := "проверочная-строка-достаточной-длины-для-pkce-1234567890"
	code, _ := h.consent(t, clientID, redirectURI, pkce(verifier), ScopeRead+" "+ScopeWrite+" "+ScopeOfflineAccess, true)
	if code == "" {
		t.Fatal("код авторизации не выдан")
	}

	tok := h.exchange(t, clientID, code, verifier, redirectURI)

	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatal("не выдан access_token")
	}
	if tok["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", tok["token_type"])
	}
	if tok["refresh_token"] == nil {
		t.Error("при offline_access должен выдаваться refresh_token")
	}

	validated, err := h.oauth.Validate(context.Background(), access)
	if err != nil {
		t.Fatalf("выданный токен не проходит проверку: %v", err)
	}
	if !validated.HasScope(ScopeWrite) {
		t.Error("подтверждена запись, но её нет в токене")
	}
	if validated.UserID != 1 || validated.MailboxID != 10 {
		t.Errorf("токен привязан не к тому: %+v", validated.Subject)
	}
	if validated.HasScope(ScopeSend) {
		t.Error("отправку не отмечали, а она в токене есть")
	}

	// Клиент показывает человеку, к какому ящику он подключён.
	mb, _ := tok["mailbox"].(map[string]any)
	want := h.accounts.boxes[1][0]
	if mb == nil || mb["name"] != want.Name || mb["email"] != want.Email {
		t.Errorf("в ответе нет ящика выдачи %+v: %v", want, tok["mailbox"])
	}
}

func TestUserCanNarrowScopesAtConsent(t *testing.T) {
	// Смысл экрана согласия: решает пользователь, а не клиент. Клиент
	// просит запись, пользователь её не даёт — токен выходит без неё.
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"

	clientID := h.register(t, redirectURI)
	verifier := "verifier-для-телефона-1234567890123456789012345"

	code, _ := h.consent(t, clientID, redirectURI, pkce(verifier), ScopeRead+" "+ScopeWrite, false)
	tok := h.exchange(t, clientID, code, verifier, redirectURI)

	validated, err := h.oauth.Validate(context.Background(), tok["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if validated.HasScope(ScopeWrite) {
		t.Fatal("владелец не давал права записи, а оно в токене есть")
	}
	if !validated.HasScope(ScopeRead) {
		t.Error("чтение должно остаться")
	}
}

// openConsent открывает экран согласия и возвращает ответ.
func (h *harness) openConsent(t *testing.T, clientID, redirectURI string) (*http.Response, string) {
	t.Helper()
	verifier := "verifier-1234567890123456789012345678901234567"
	authURL := h.srv.URL + "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {pkce(verifier)},
		"code_challenge_method": {"S256"},
		"scope":                 {ScopeRead},
	}.Encode()

	resp, err := h.client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(page)
}

func TestAnonymousIsSentToLoginAndBack(t *testing.T) {
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	clientID := h.register(t, redirectURI)

	h.loginAs("")
	resp, _ := h.openConsent(t, clientID, redirectURI)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("без входа ожидался редирект, получен %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Path != "/login" {
		t.Fatalf("редирект не на вход: %s", loc)
	}
	next := loc.Query().Get("next")
	if !strings.HasPrefix(next, "/oauth/authorize?") || !strings.Contains(next, clientID) {
		t.Fatalf("после входа не вернуться к согласию: next=%q", next)
	}
}

func TestUserWithoutMailboxesIsSentToAddMailbox(t *testing.T) {
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	clientID := h.register(t, redirectURI)

	h.loginAs("3")
	resp, _ := h.openConsent(t, clientID, redirectURI)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("ожидался редирект, получен %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/account/mailboxes/new") {
		t.Fatalf("редирект не на подключение ящика: %s", loc)
	}
}

func TestConsentListsOnlyOwnMailboxes(t *testing.T) {
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	clientID := h.register(t, redirectURI)

	_, page := h.openConsent(t, clientID, redirectURI)
	if !strings.Contains(page, "alex@work.example") || !strings.Contains(page, "alex@home.example") {
		t.Fatal("на согласии нет ящиков пользователя")
	}
	if strings.Contains(page, "foreign") {
		t.Fatal("на согласии виден чужой ящик")
	}
}

func TestForeignMailboxDoesNotIssueCode(t *testing.T) {
	// Номер ящика из формы — это ввод: подставив чужой, нельзя
	// получить доступ к чужой почте.
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	clientID := h.register(t, redirectURI)

	_, page := h.openConsent(t, clientID, redirectURI)
	sessionID := extractSession(t, page)

	resp, err := h.client.PostForm(h.srv.URL+"/oauth/authorize", url.Values{
		"session":    {sessionID},
		"action":     {"allow"},
		"mailbox":    {"20"},
		"scope_read": {"on"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Fatal("с чужим ящиком код выдаваться не должен")
	}
}

func TestOtherUserCannotSubmitSession(t *testing.T) {
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	clientID := h.register(t, redirectURI)

	_, page := h.openConsent(t, clientID, redirectURI)
	sessionID := extractSession(t, page)

	h.loginAs("2")
	resp, err := h.client.PostForm(h.srv.URL+"/oauth/authorize", url.Values{
		"session":    {sessionID},
		"action":     {"allow"},
		"mailbox":    {"20"},
		"scope_read": {"on"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("чужая сессия согласия: ожидался 403, получен %d", resp.StatusCode)
	}
}

func TestPKCEMismatchRejected(t *testing.T) {
	// Перехваченный код бесполезен без verifier — ради этого PKCE и есть.
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"

	clientID := h.register(t, redirectURI)
	verifier := "настоящий-verifier-12345678901234567890123456"

	code, _ := h.consent(t, clientID, redirectURI, pkce(verifier), ScopeRead, false)

	resp, err := h.client.PostForm(h.srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {"чужой-verifier-1234567890123456789012345678"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("чужой verifier должен отклоняться, статус %d", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "invalid_grant" {
		t.Errorf("код ошибки = %v, want invalid_grant", out["error"])
	}
}

func TestAuthCodeIsSingleUse(t *testing.T) {
	// Повторное использование кода — признак перехвата.
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"

	clientID := h.register(t, redirectURI)
	verifier := "verifier-одноразовый-12345678901234567890123"

	code, _ := h.consent(t, clientID, redirectURI, pkce(verifier), ScopeRead, false)
	h.exchange(t, clientID, code, verifier, redirectURI) // первый раз — успех

	resp, err := h.client.PostForm(h.srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("повторный обмен кода должен отклоняться, статус %d", resp.StatusCode)
	}
}

func TestRefreshRotatesAndInvalidatesOldTokens(t *testing.T) {
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"

	clientID := h.register(t, redirectURI)
	verifier := "verifier-для-обновления-123456789012345678901"

	code, _ := h.consent(t, clientID, redirectURI, pkce(verifier), ScopeRead+" "+ScopeOfflineAccess, false)
	first := h.exchange(t, clientID, code, verifier, redirectURI)

	oldAccess := first["access_token"].(string)
	oldRefresh := first["refresh_token"].(string)

	resp, err := h.client.PostForm(h.srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldRefresh},
		"client_id":     {clientID},
	})
	if err != nil {
		t.Fatal(err)
	}
	var second map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&second)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("обновление должно проходить, статус %d, тело %v", resp.StatusCode, second)
	}

	newRefresh, _ := second["refresh_token"].(string)
	if newRefresh == "" || newRefresh == oldRefresh {
		t.Error("refresh должен ротироваться: OAuth 2.1 требует этого для публичных клиентов")
	}

	// Старый access обязан умереть вместе с выдачей, иначе отзыв
	// ничего не отзывает.
	if _, err := h.oauth.Validate(context.Background(), oldAccess); err == nil {
		t.Error("старый access-токен должен становиться недействительным после обновления")
	}
	renewed, err := h.oauth.Validate(context.Background(), second["access_token"].(string))
	if err != nil {
		t.Fatalf("новый access-токен должен работать: %v", err)
	}
	// Магазин переживает обновление: иначе через час подключение
	// молча переключилось бы в никуда.
	if renewed.MailboxID != 10 || renewed.UserID != 1 {
		t.Errorf("после обновления потерялась привязка: %+v", renewed.Subject)
	}
}

func TestReusedRefreshTokenRejectedWithInvalidGrant(t *testing.T) {
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"

	clientID := h.register(t, redirectURI)
	verifier := "verifier-повторное-обновление-1234567890123"

	code, _ := h.consent(t, clientID, redirectURI, pkce(verifier), ScopeRead+" "+ScopeOfflineAccess, false)
	first := h.exchange(t, clientID, code, verifier, redirectURI)
	refresh := first["refresh_token"].(string)

	// Используем один раз.
	resp, _ := h.client.PostForm(h.srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	resp.Body.Close()

	// И ещё раз тем же.
	resp2, err := h.client.PostForm(h.srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	var out map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&out)

	// Именно invalid_grant: по нему Claude поймёт, что надо заново
	// пройти согласие, а не повторять обновление до бесконечности.
	if out["error"] != "invalid_grant" {
		t.Errorf("код ошибки = %v, want invalid_grant", out["error"])
	}
}

func TestRevokeKillsWholeGrant(t *testing.T) {
	// То, ради чего вообще затевался OAuth: отозвать доступ одного
	// устройства, не трогая остальные.
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"

	clientID := h.register(t, redirectURI)
	verifier := "verifier-для-отзыва-12345678901234567890123"

	code, _ := h.consent(t, clientID, redirectURI, pkce(verifier), ScopeRead+" "+ScopeOfflineAccess, false)
	tok := h.exchange(t, clientID, code, verifier, redirectURI)

	access := tok["access_token"].(string)
	refresh := tok["refresh_token"].(string)

	resp, err := h.client.PostForm(h.srv.URL+"/oauth/revoke", url.Values{"token": {access}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if _, err := h.oauth.Validate(context.Background(), access); err == nil {
		t.Error("отозванный access-токен всё ещё действует")
	}

	// И refresh тоже: иначе доступ вернётся первым же обновлением.
	resp2, err := h.client.PostForm(h.srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == http.StatusOK {
		t.Fatal("после отзыва refresh не должен выпускать новые токены")
	}
}

func TestUnknownTokenRevocationIsSuccess(t *testing.T) {
	// RFC 7009: иначе эндпоинт становится оракулом «существует ли токен».
	h := newHarness(t)

	resp, err := h.client.PostForm(h.srv.URL+"/oauth/revoke", url.Values{"token": {"такого-нет"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("отзыв неизвестного токена должен возвращать 200, получен %d", resp.StatusCode)
	}
}

func TestTokenForOtherResourceRejected(t *testing.T) {
	// Подлинный токен, выпущенный для другого сервиса, не должен
	// открывать этот. Без проверки audience один общий провайдер
	// личности открывал бы все сервисы сразу.
	h := newHarness(t)

	store := NewMemoryStore()
	access := "чужой-токен"
	err := store.SaveTokens(context.Background(), &Token{
		TokenHash: hashToken(access),
		ClientID:  "someone",
		Scopes:    []string{ScopeRead},
		Resource:  "https://другой-сервис.example/mcp",
		ExpiresAt: timeNowPlusHour(),
		GrantID:   "g1",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	h.oauth.store = store
	if _, err := h.oauth.Validate(context.Background(), access); err == nil {
		t.Fatal("токен для другого ресурса должен отклоняться")
	}
}

func TestRedirectURIMustBeRegistered(t *testing.T) {
	// Иначе сервер становится инструментом открытого редиректа.
	h := newHarness(t)
	clientID := h.register(t, "https://claude.ai/api/mcp/auth_callback")

	resp, err := h.client.Get(h.srv.URL + "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://злоумышленник.example/забрать"},
		"code_challenge":        {pkce("v")},
		"code_challenge_method": {"S256"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("незарегистрированный адрес возврата должен отклоняться, статус %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("на ошибку в самом redirect_uri нельзя отвечать перенаправлением: %s", loc)
	}
}

func TestPKCERequired(t *testing.T) {
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	clientID := h.register(t, redirectURI)

	resp, err := h.client.Get(h.srv.URL + "/oauth/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("ожидалось перенаправление с ошибкой, статус %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("без PKCE ожидалась ошибка invalid_request, получено %q", loc.Query().Get("error"))
	}
}

func timeNowPlusHour() time.Time { return time.Now().Add(time.Hour) }

func TestAllMailboxesAndSendScope(t *testing.T) {
	// «Все ящики» — это mailbox=0 и подключение ко всему, что есть и
	// появится; отправка выдаётся только отдельной галочкой.
	h := newHarness(t)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	clientID := h.register(t, redirectURI)

	verifier := "verifier-всех-ящиков-1234567890123456789012345"
	_, page := func() (*http.Response, string) {
		authURL := h.srv.URL + "/oauth/authorize?" + url.Values{
			"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
			"code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"},
			"scope": {ScopeRead + " " + ScopeSend},
		}.Encode()
		resp, err := h.client.Get(authURL)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}()
	resp, err := h.client.PostForm(h.srv.URL+"/oauth/authorize", url.Values{
		"session": {extractSession(t, page)}, "action": {"allow"}, "mailbox": {"0"}, "scope_send": {"on"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("код не выдан: %s", resp.Header.Get("Location"))
	}
	tok := h.exchange(t, clientID, code, verifier, redirectURI)
	v, err := h.oauth.Validate(context.Background(), tok["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if v.MailboxID != 0 || !v.HasScope(ScopeSend) || !v.HasScope(ScopeRead) || v.HasScope(ScopeWrite) {
		t.Fatalf("выдача: ящик %d, права %v", v.MailboxID, v.Scopes)
	}
	if mb, _ := tok["mailbox"].(map[string]any); mb == nil || mb["all"] != true {
		t.Fatalf("ответ должен сообщать, что подключены все ящики: %v", tok["mailbox"])
	}
}
