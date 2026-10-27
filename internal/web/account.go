package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/MainAlexStark/email-mcp/internal/httpx"
	"github.com/MainAlexStark/email-mcp/internal/mailboxes"
	"github.com/MainAlexStark/email-mcp/internal/pgstore"
	"github.com/MainAlexStark/email-mcp/internal/secure"
	"github.com/MainAlexStark/email-mcp/mail"
)

// flashes — сообщения после действий. Код в адресе, а не текст:
// иначе ссылкой можно подсунуть человеку любую фразу от имени сервиса.
var flashes = map[string]string{
	"mailbox_added":   "Ящик подключён. Теперь добавьте сервер в Claude — адрес выше.",
	"mailbox_ok":      "Вход проверен: сервер пускает.",
	"mailbox_saved":   "Настройки ящика сохранены и проверены.",
	"mailbox_deleted": "Ящик удалён вместе с подключениями и токенами, привязанными только к нему.",
	"grant_revoked":   "Подключение отозвано — приложение потеряло доступ немедленно.",
	"token_deleted":   "Токен отозван.",
	"password":        "Пароль изменён. Остальные браузеры вышли из кабинета.",
}

type mailboxView struct {
	pgstore.Mailbox
	CheckedAgo string
}

type accountView struct {
	Email       string
	Plan        string
	CSRF        string
	ResourceURL string
	Flash       string
	Error       string
	Mailboxes   []mailboxView
	Grants      []pgstore.Grant
	Tokens      []pgstore.APIToken
	Calls30d    int64
	NewToken    string
	NewTokenFor string
}

func (w *Web) account(rw http.ResponseWriter, r *request) {
	w.renderAccount(rw, r, http.StatusOK, flashes[r.URL.Query().Get("ok")], "", nil)
}

// renderAccount собирает кабинет. extra дописывает вид (новый токен).
func (w *Web) renderAccount(rw http.ResponseWriter, r *request, status int, flash, errMsg string, extra func(*accountView)) {
	ctx := r.Context()
	uid := r.sess.UserID

	user, err := w.db.UserByID(ctx, uid)
	if err != nil {
		w.fail(rw, err)
		return
	}
	list, err := w.db.Mailboxes(ctx, uid)
	if err != nil {
		w.fail(rw, err)
		return
	}
	grants, err := w.db.UserGrants(ctx, uid)
	if err != nil {
		w.fail(rw, err)
		return
	}
	tokens, err := w.db.APITokens(ctx, uid)
	if err != nil {
		w.fail(rw, err)
		return
	}
	calls, err := w.db.UsageSince(ctx, uid, 30)
	if err != nil {
		w.fail(rw, err)
		return
	}

	view := accountView{
		Email:       user.Email,
		Plan:        user.Plan,
		CSRF:        r.sess.CSRF,
		ResourceURL: w.cfg.ResourceURL,
		Flash:       flash,
		Error:       errMsg,
		Grants:      grants,
		Tokens:      tokens,
		Calls30d:    calls,
	}
	for _, m := range list {
		v := mailboxView{Mailbox: m}
		if m.CheckedAt != nil {
			v.CheckedAgo = m.CheckedAt.Format("02.01.2006 15:04")
		}
		view.Mailboxes = append(view.Mailboxes, v)
	}
	if extra != nil {
		extra(&view)
	}
	w.render(rw, status, "account", view)
}

// --- ящики ---

type mailboxFormView struct {
	CSRF     string
	Next     string
	Form     mailboxes.Form
	Error    string
	First    bool
	Edit     bool
	ID       int64
	Provider *mail.Provider
	Advanced bool
}

func formFromRequest(r *request) mailboxes.Form {
	v := r.PostFormValue
	return mailboxes.Form{
		Name: v("name"), Email: v("email"), DisplayName: v("display_name"),
		IMAPHost: v("imap_host"), IMAPPort: v("imap_port"), IMAPSecurity: v("imap_security"),
		SMTPHost: v("smtp_host"), SMTPPort: v("smtp_port"), SMTPSecurity: v("smtp_security"),
		Username: v("username"), Password: v("password"),
	}
}

func (w *Web) mailboxForm(rw http.ResponseWriter, r *request) {
	list, err := w.db.Mailboxes(r.Context(), r.sess.UserID)
	if err != nil {
		w.fail(rw, err)
		return
	}
	w.render(rw, http.StatusOK, "mailbox_form", mailboxFormView{
		CSRF:  r.sess.CSRF,
		Next:  safeNext(r.URL.Query().Get("next")),
		First: len(list) == 0,
	})
}

// maxMailboxesPerUser — потолок ящиков на пользователя: защита от
// злоупотребления, а не тарифное ограничение.
const maxMailboxesPerUser = 20

func (w *Web) mailboxAdd(rw http.ResponseWriter, r *request) {
	view := mailboxFormView{
		CSRF: r.sess.CSRF,
		Next: safeNext(r.PostFormValue("next")),
		Form: formFromRequest(r),
	}
	list, err := w.db.Mailboxes(r.Context(), r.sess.UserID)
	if err != nil {
		w.fail(rw, err)
		return
	}
	view.First = len(list) == 0
	if len(list) >= maxMailboxesPerUser {
		view.Error = "Достигнут предел ящиков на одну учётную запись."
		w.render(rw, http.StatusBadRequest, "mailbox_form", view)
		return
	}

	_, err = w.boxes.Connect(r.Context(), r.sess.UserID, view.Form)
	if err != nil {
		w.renderMailboxError(rw, &view, err)
		return
	}
	w.logger.Info("ящик подключён", "user", r.sess.UserID)

	next := view.Next
	if next == "/account" {
		next = "/account?ok=mailbox_added"
	}
	http.Redirect(rw, r.Request, next, http.StatusFound)
}

// renderMailboxError показывает форму с ошибкой. Пароль в форму не
// возвращается: его придётся ввести заново, зато он не оседает в HTML.
func (w *Web) renderMailboxError(rw http.ResponseWriter, view *mailboxFormView, err error) {
	view.Error = userMessage(err)
	if view.Error == "" {
		w.logger.Error("подключение ящика", "err", err)
		view.Error = "Не удалось проверить ящик: " + err.Error()
	}
	view.Form.Password = ""
	if p, ok := view.Form.Autofill(); ok {
		view.Provider = &p
	}
	// Ошибка в настройках сервера — раскрываем расширенные поля, чтобы
	// человеку было что исправлять.
	view.Advanced = view.Provider == nil || view.Form.IMAPHost != view.Provider.IMAP.Host
	w.render(rw, http.StatusBadRequest, "mailbox_form", *view)
}

func (w *Web) mailboxEditForm(rw http.ResponseWriter, r *request) {
	id, ok := pathID(r)
	if !ok {
		w.notFound(rw, r.Request)
		return
	}
	m, err := w.db.Mailbox(r.Context(), r.sess.UserID, id)
	if err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			w.notFound(rw, r.Request)
			return
		}
		w.fail(rw, err)
		return
	}
	w.render(rw, http.StatusOK, "mailbox_form", mailboxFormView{
		CSRF: r.sess.CSRF, Next: "/account", Edit: true, ID: id, Advanced: true,
		Form: mailboxes.Form{
			Name: m.Name, Email: m.Email, DisplayName: m.DisplayName,
			IMAPHost: m.IMAPHost, IMAPPort: strconv.Itoa(m.IMAPPort), IMAPSecurity: m.IMAPSecurity,
			SMTPHost: m.SMTPHost, SMTPPort: portString(m.SMTPPort), SMTPSecurity: m.SMTPSecurity,
			Username: m.Username,
		},
	})
}

func portString(p int) string {
	if p == 0 {
		return ""
	}
	return strconv.Itoa(p)
}

func (w *Web) mailboxEdit(rw http.ResponseWriter, r *request) {
	id, ok := pathID(r)
	if !ok {
		w.notFound(rw, r.Request)
		return
	}
	view := mailboxFormView{CSRF: r.sess.CSRF, Next: "/account", Edit: true, ID: id, Form: formFromRequest(r)}
	if err := w.boxes.Update(r.Context(), r.sess.UserID, id, view.Form); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			w.notFound(rw, r.Request)
			return
		}
		view.Advanced = true
		w.renderMailboxError(rw, &view, err)
		return
	}
	http.Redirect(rw, r.Request, "/account?ok=mailbox_saved", http.StatusFound)
}

func (w *Web) mailboxCheck(rw http.ResponseWriter, r *request) {
	id, ok := pathID(r)
	if !ok {
		w.notFound(rw, r.Request)
		return
	}
	if err := w.boxes.Check(r.Context(), r.sess.UserID, id); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			w.notFound(rw, r.Request)
			return
		}
		msg := userMessage(err)
		if msg == "" {
			msg = err.Error()
		}
		w.renderAccount(rw, r, http.StatusOK, "", "Проверка не прошла: "+msg, nil)
		return
	}
	http.Redirect(rw, r.Request, "/account?ok=mailbox_ok", http.StatusFound)
}

func (w *Web) mailboxDelete(rw http.ResponseWriter, r *request) {
	id, ok := pathID(r)
	if !ok {
		w.notFound(rw, r.Request)
		return
	}
	if err := w.db.DeleteMailbox(r.Context(), r.sess.UserID, id); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			w.notFound(rw, r.Request)
			return
		}
		w.fail(rw, err)
		return
	}
	w.logger.Info("ящик удалён", "user", r.sess.UserID, "mailbox", id)
	http.Redirect(rw, r.Request, "/account?ok=mailbox_deleted", http.StatusFound)
}

// --- подключения ---

func (w *Web) grantRevoke(rw http.ResponseWriter, r *request) {
	if err := w.db.RevokeUserGrant(r.Context(), r.sess.UserID, r.PathValue("id")); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			w.notFound(rw, r.Request)
			return
		}
		w.fail(rw, err)
		return
	}
	http.Redirect(rw, r.Request, "/account?ok=grant_revoked", http.StatusFound)
}

// --- токены ---

const maxTokensPerUser = 20

func (w *Web) tokenCreate(rw http.ResponseWriter, r *request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		name = "Токен"
	}
	if utf8.RuneCountInString(name) > 60 {
		w.renderAccount(rw, r, http.StatusBadRequest, "", "Название токена длиннее 60 символов.", nil)
		return
	}
	mailboxID, _ := strconv.ParseInt(r.PostFormValue("mailbox"), 10, 64)

	existing, err := w.db.APITokens(r.Context(), r.sess.UserID)
	if err != nil {
		w.fail(rw, err)
		return
	}
	if len(existing) >= maxTokensPerUser {
		w.renderAccount(rw, r, http.StatusBadRequest, "", "Достигнут предел токенов — отзовите ненужные.", nil)
		return
	}

	scopes := []string{"read"}
	for _, sc := range []string{"drafts", "write", "send"} {
		if r.PostFormValue(sc) == "on" {
			scopes = append(scopes, sc)
		}
	}

	raw, err := secure.RandomToken()
	if err != nil {
		w.fail(rw, err)
		return
	}
	token := httpx.APITokenPrefix + raw

	if _, err := w.db.CreateAPIToken(r.Context(), r.sess.UserID, mailboxID, name,
		secure.HashToken(token), scopes); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			w.renderAccount(rw, r, http.StatusBadRequest, "", "Выберите ящик для токена.", nil)
			return
		}
		w.fail(rw, err)
		return
	}
	w.logger.Info("выпущен API-токен", "user", r.sess.UserID, "mailbox", mailboxID, "scopes", scopes)

	// Токен показывается один раз, прямо в ответе на POST: в базе
	// только хеш, и повторить его потом невозможно.
	w.renderAccount(rw, r, http.StatusOK, "", "", func(v *accountView) {
		v.NewToken = token
		v.NewTokenFor = name
	})
}

func (w *Web) tokenDelete(rw http.ResponseWriter, r *request) {
	id, ok := pathID(r)
	if !ok {
		w.notFound(rw, r.Request)
		return
	}
	if err := w.db.DeleteAPIToken(r.Context(), r.sess.UserID, id); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			w.notFound(rw, r.Request)
			return
		}
		w.fail(rw, err)
		return
	}
	http.Redirect(rw, r.Request, "/account?ok=token_deleted", http.StatusFound)
}

// --- учётная запись ---

func (w *Web) passwordChange(rw http.ResponseWriter, r *request) {
	if !w.limiter.allow(w.cfg.ClientIP(r.Request)) {
		w.message(rw, http.StatusTooManyRequests, "Слишком много попыток", "Подождите минуту.")
		return
	}
	user, err := w.db.UserByID(r.Context(), r.sess.UserID)
	if err != nil {
		w.fail(rw, err)
		return
	}
	if !secure.VerifyPassword(user.PasswordHash, r.PostFormValue("current")) {
		w.renderAccount(rw, r, http.StatusBadRequest, "", "Текущий пароль указан неверно.", nil)
		return
	}
	next := r.PostFormValue("new")
	if next != r.PostFormValue("new2") {
		w.renderAccount(rw, r, http.StatusBadRequest, "", "Новые пароли не совпадают.", nil)
		return
	}
	hash, err := secure.HashPassword(next)
	if errors.Is(err, secure.ErrShortPassword) {
		w.renderAccount(rw, r, http.StatusBadRequest, "", "Новый пароль короче 8 символов.", nil)
		return
	}
	if err != nil {
		w.fail(rw, err)
		return
	}
	if err := w.db.SetPassword(r.Context(), user.ID, hash, r.sessHash); err != nil {
		w.fail(rw, err)
		return
	}
	http.Redirect(rw, r.Request, "/account?ok=password", http.StatusFound)
}

func (w *Web) accountDelete(rw http.ResponseWriter, r *request) {
	if !w.limiter.allow(w.cfg.ClientIP(r.Request)) {
		w.message(rw, http.StatusTooManyRequests, "Слишком много попыток", "Подождите минуту.")
		return
	}
	user, err := w.db.UserByID(r.Context(), r.sess.UserID)
	if err != nil {
		w.fail(rw, err)
		return
	}
	if !secure.VerifyPassword(user.PasswordHash, r.PostFormValue("password")) {
		w.renderAccount(rw, r, http.StatusBadRequest, "", "Пароль указан неверно — учётная запись не удалена.", nil)
		return
	}
	if err := w.db.DeleteUser(r.Context(), user.ID); err != nil {
		w.fail(rw, err)
		return
	}
	w.logger.Info("учётная запись удалена", "user", user.ID)
	w.clearCookie(rw)
	w.message(rw, http.StatusOK, "Учётная запись удалена",
		"Пароли ящиков, подключения и токены удалены. Доступ всех приложений прекращён.")
}

func pathID(r *request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// userMessage — текст ошибки, который можно показать человеку.
func userMessage(err error) string {
	var in *mailboxes.InputError
	if errors.As(err, &in) {
		return in.Msg
	}
	if mail.IsInput(err) {
		return err.Error()
	}
	return ""
}
