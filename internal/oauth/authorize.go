package oauth

import (
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/MainAlexStark/email-mcp/internal/ui"
)

// handleAuthorize — начало потока: показываем форму входа и согласия.
//
// Порядок проверок важен. Всё, что связано с redirect_uri, проверяется
// ДО того, как мы соглашаемся куда-то перенаправлять: ошибку в самом
// адресе возврата нельзя сообщать перенаправлением на него же, иначе
// сервер превращается в инструмент открытого редиректа.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")

	client, err := s.store.Client(r.Context(), clientID)
	if err != nil {
		// Клиент неизвестен — перенаправлять некуда, показываем страницу.
		s.renderError(w, http.StatusBadRequest,
			"Неизвестное приложение",
			"Клиент с таким client_id не зарегистрирован. Попробуйте подключить сервер в Claude заново.")
		return
	}

	if !redirectURIAllowed(client.RedirectURIs, redirectURI) {
		s.renderError(w, http.StatusBadRequest,
			"Недопустимый адрес возврата",
			"Адрес redirect_uri не совпадает с зарегистрированным. Это защита от перенаправления на чужой сайт.")
		return
	}

	// С этого момента ошибки можно возвращать клиенту перенаправлением.

	if q.Get("response_type") != "code" {
		s.redirectError(w, r, redirectURI, q.Get("state"), "unsupported_response_type",
			"поддерживается только response_type=code")
		return
	}

	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if challenge == "" || method != "S256" {
		s.redirectError(w, r, redirectURI, q.Get("state"), "invalid_request",
			"обязателен PKCE с code_challenge_method=S256")
		return
	}

	// RFC 8707: токен выпускается для конкретного ресурса. Если клиент
	// не сказал, для какого, считаем, что для нашего единственного.
	resource := q.Get("resource")
	if resource == "" {
		resource = s.cfg.ResourceURL
	}
	if !sameResource(resource, s.cfg.ResourceURL) {
		s.redirectError(w, r, redirectURI, q.Get("state"), "invalid_target",
			"запрошен токен для другого ресурса: "+resource)
		return
	}

	requested := parseScopes(q.Get("scope"))
	if len(requested) == 0 {
		requested = []string{ScopeRead}
	}

	// Кто подключает. Не вошёл — на вход и обратно сюда же: весь
	// запрос авторизации переживает круг через форму входа в адресе.
	user, ok := s.accounts.CurrentUser(r)
	if !ok {
		http.Redirect(w, r, s.accounts.LoginURL(r.URL.RequestURI()), http.StatusFound)
		return
	}

	boxes, err := s.accounts.Mailboxes(r.Context(), user.ID)
	if err != nil {
		s.redirectError(w, r, redirectURI, q.Get("state"), "server_error", "не удалось прочитать ящики")
		return
	}
	// Без ящика подключать нечего: сначала ящик, потом сюда.
	if len(boxes) == 0 {
		http.Redirect(w, r, s.accounts.AddMailboxURL(r.URL.RequestURI()), http.StatusFound)
		return
	}

	sessionID, err := randomToken()
	if err != nil {
		s.redirectError(w, r, redirectURI, q.Get("state"), "server_error", "не удалось начать сессию")
		return
	}

	sess := &LoginSession{
		ID:            sessionID,
		ClientID:      client.ID,
		RedirectURI:   redirectURI,
		State:         q.Get("state"),
		Scopes:        requested,
		Resource:      resource,
		CodeChallenge: challenge,
		UserID:        user.ID,
		ExpiresAt:     time.Now().Add(LoginSessionTTL),
	}
	if err := s.store.SaveSession(r.Context(), sess); err != nil {
		s.redirectError(w, r, redirectURI, q.Get("state"), "server_error", "не удалось сохранить сессию")
		return
	}

	s.renderConsent(w, client, sess, user, boxes, "")
}

// handleAuthorizeSubmit — пользователь выбрал ящики и права.
func (s *Server) handleAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, http.StatusBadRequest, "Не разобрана форма", err.Error())
		return
	}

	ctx := r.Context()
	sessionID := r.PostFormValue("session")
	sess, err := s.store.Session(ctx, sessionID)
	if err != nil {
		s.renderError(w, http.StatusBadRequest,
			"Время истекло",
			"Страница подтверждения устарела. Начните подключение в Claude заново.")
		return
	}

	client, err := s.store.Client(ctx, sess.ClientID)
	if err != nil {
		s.renderError(w, http.StatusBadRequest, "Неизвестное приложение", "Клиент не найден.")
		return
	}

	// Подтвердить может только тот, кто открыл форму. Номер сессии
	// в скрытом поле непредсказуем, но сверка с cookie закрывает и тот
	// случай, когда он всё же утёк: чужим браузером его не отправить.
	user, ok := s.accounts.CurrentUser(r)
	if !ok || user.ID != sess.UserID {
		s.renderError(w, http.StatusForbidden,
			"Сессия не ваша",
			"Эта страница подтверждения открыта под другой учётной записью. Начните подключение в Claude заново.")
		return
	}

	// Отказ — обычный исход, а не ошибка.
	if r.PostFormValue("action") != "allow" {
		_, _ = s.store.TakeSession(ctx, sessionID)
		s.redirectError(w, r, sess.RedirectURI, sess.State, "access_denied", "пользователь отклонил подключение")
		return
	}

	boxes, err := s.accounts.Mailboxes(ctx, user.ID)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Ошибка", "Не удалось прочитать ящики.")
		return
	}

	// Ящик сверяется со списком самого пользователя: номер из формы —
	// это ввод, и чужой номер не должен давать доступ к чужому ящику.
	// 0 — «все ящики».
	mailboxID, err := strconv.ParseInt(r.PostFormValue("mailbox"), 10, 64)
	if err != nil || mailboxID < 0 {
		s.renderConsent(w, client, sess, user, boxes, "Выберите ящик.")
		return
	}
	var picked *Mailbox
	for i := range boxes {
		if boxes[i].ID == mailboxID {
			picked = &boxes[i]
		}
	}
	if mailboxID != 0 && picked == nil {
		s.renderConsent(w, client, sess, user, boxes, "Выберите ящик.")
		return
	}

	// Права берём из галочек, а не из того, что запросил клиент:
	// смысл экрана согласия в том, что решает пользователь. Чтение
	// выдаётся всегда — без него остальные права бессмысленны: нельзя
	// ответить на письмо, которое не можешь прочитать.
	granted := []string{ScopeRead}
	for _, sc := range []string{ScopeDrafts, ScopeWrite, ScopeSend} {
		if r.PostFormValue("scope_"+strings.TrimPrefix(sc, "mail:")) == "on" {
			granted = append(granted, sc)
		}
	}
	// offline_access отдаём, если его просили: без него Claude будет
	// требовать подтверждение каждый час.
	if containsScope(sess.Scopes, ScopeOfflineAccess) {
		granted = append(granted, ScopeOfflineAccess)
	}

	if _, err := s.store.TakeSession(ctx, sessionID); err != nil {
		s.renderError(w, http.StatusBadRequest, "Время истекло", "Начните подключение заново.")
		return
	}

	code, err := randomToken()
	if err != nil {
		s.redirectError(w, r, sess.RedirectURI, sess.State, "server_error", "не удалось выдать код")
		return
	}

	err = s.store.SaveCode(ctx, &AuthCode{
		CodeHash:      hashToken(code),
		Subject:       Subject{UserID: user.ID, MailboxID: mailboxID},
		ClientID:      sess.ClientID,
		RedirectURI:   sess.RedirectURI,
		Scopes:        granted,
		Resource:      sess.Resource,
		CodeChallenge: sess.CodeChallenge,
		ExpiresAt:     time.Now().Add(AuthCodeTTL),
	})
	if err != nil {
		s.redirectError(w, r, sess.RedirectURI, sess.State, "server_error", "не удалось сохранить код")
		return
	}

	s.logger.Info("доступ разрешён",
		"client", client.Name,
		"client_id", client.ID,
		"user", user.ID,
		"mailbox", mailboxID,
		"scopes", granted)

	u, _ := url.Parse(sess.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	if sess.State != "" {
		q.Set("state", sess.State)
	}
	// RFC 9207: клиент должен убедиться, что ответ пришёл от того же
	// издателя, у которого он начинал поток.
	q.Set("iss", s.cfg.Issuer)
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// redirectError возвращает ошибку клиенту через адрес возврата.
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		s.renderError(w, http.StatusBadRequest, "Ошибка", description)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", s.cfg.Issuer)
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// sameResource сравнивает адреса ресурса, прощая завершающий слэш.
func sameResource(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

func parseScopes(s string) []string {
	var out []string
	for _, f := range strings.Fields(s) {
		out = append(out, f)
	}
	return out
}

func containsScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// --- Страницы ---

type consentView struct {
	SessionID    string
	ClientName   string
	RedirectHost string
	IsLoopback   bool
	WantsWrite   bool
	WantsSend    bool
	Email        string
	Mailboxes    []Mailbox
	Style        template.CSS
	Error        string
}

// renderConsent показывает экран согласия.
func (s *Server) renderConsent(w http.ResponseWriter, client *Client, sess *LoginSession, user User, boxes []Mailbox, errMsg string) {
	host := sess.RedirectURI
	if u, err := url.Parse(sess.RedirectURI); err == nil {
		host = u.Host
		if host == "" {
			host = u.String()
		}
	}

	view := consentView{
		SessionID:    sess.ID,
		ClientName:   client.Name,
		RedirectHost: host,
		IsLoopback:   isLoopbackRedirect(client.RedirectURIs),
		WantsWrite:   containsScope(sess.Scopes, ScopeWrite),
		WantsSend:    containsScope(sess.Scopes, ScopeSend),
		Email:        user.Email,
		Mailboxes:    boxes,
		Style:        ui.Style,
		Error:        errMsg,
	}

	ui.NoCache(w)
	if errMsg != "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = consentTemplate.Execute(w, view)
}

// isLoopbackRedirect — все адреса возврата ведут на эту же машину.
//
// Такой клиент невозможно отличить от любого другого процесса на том же
// компьютере, поэтому спецификация требует предупредить об этом явно.
func isLoopbackRedirect(uris []string) bool {
	if len(uris) == 0 {
		return false
	}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || !isLoopbackHost(u.Hostname()) {
			return false
		}
	}
	return true
}

func (s *Server) renderError(w http.ResponseWriter, status int, title, message string) {
	ui.RenderMessage(w, status, title, message)
}

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Доступ к почте</title><style>{{.Style}}</style></head>
<body><div class="card">
<h1>Разрешить доступ к почте?</h1>
<p class="sub">Приложение запрашивает доступ к вашим почтовым ящикам.</p>

{{if .Error}}<div class="err">{{.Error}}</div>{{end}}

<div class="row"><span>Приложение</span><span>{{.ClientName}}</span></div>
<div class="row"><span>Вернётся на</span><span class="mono">{{.RedirectHost}}</span></div>
<div class="row"><span>Учётная запись</span><span>{{.Email}}</span></div>

{{if .IsLoopback}}
<div class="warn">Приложение возвращается на адрес вашего же компьютера.
Убедитесь, что вы только что сами начали подключение — такой адрес может
занять любая программа на этой машине.</div>
{{end}}

<form method="post" action="/oauth/authorize">
<input type="hidden" name="session" value="{{.SessionID}}">

<fieldset>
<legend>Ящики</legend>
<label class="check">
  <input type="radio" name="mailbox" value="0" checked>
  <span><b>Все ящики</b><small>В том числе те, что вы подключите позже</small></span>
</label>
{{range .Mailboxes}}
<label class="check">
  <input type="radio" name="mailbox" value="{{.ID}}">
  <span><b>Только {{.Name}}</b><small>{{.Email}}</small></span>
</label>
{{end}}
<p class="hint"><a href="/account">Подключить другой ящик</a></p>
</fieldset>

<fieldset>
<legend>Что разрешаем</legend>

<label class="check">
  <input type="checkbox" checked disabled>
  <span><b>Чтение</b><small>Поиск, письма, вложения, папки. Выдаётся всегда.</small></span>
</label>

<label class="check">
  <input type="checkbox" name="scope_drafts" checked>
  <span><b>Черновики</b><small>Готовить письма в папке «Черновики». Наружу ничего не уходит —
  вы увидите черновик в своей почте.</small></span>
</label>

<label class="check">
  <input type="checkbox" name="scope_write">
  <span><b>Изменение ящика</b><small>Флаги, перенос, удаление в корзину, папки.
  {{if .WantsWrite}}Приложение просит это право. {{end}}</small></span>
</label>

<label class="check">
  <input type="checkbox" name="scope_send">
  <span><b>Отправка</b><small>Письма от вашего имени. Отправленное не вернуть.
  {{if .WantsSend}}Приложение просит это право. {{end}}Телефону обычно не нужно — оставьте выключенным.</small></span>
</label>
</fieldset>

<div class="actions">
  <button type="submit" name="action" value="deny" class="deny">Отклонить</button>
  <button type="submit" name="action" value="allow" class="allow">Разрешить</button>
</div>
</form>
</div></body></html>`))
