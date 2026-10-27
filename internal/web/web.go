// Package web — страницы сервиса: регистрация, вход и кабинет, где
// пользователь подключает свои почтовые ящики, видит подключения Claude
// и выпускает токены для автоматизации.
//
// Страницы — серверный HTML без JavaScript: меньше движущихся частей,
// строгий Content-Security-Policy, и всё работает с телефона.
package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MainAlexStark/email-mcp/internal/mailboxes"
	"github.com/MainAlexStark/email-mcp/internal/oauth"
	"github.com/MainAlexStark/email-mcp/internal/pgstore"
	"github.com/MainAlexStark/email-mcp/internal/secure"
)

// Config — настройки кабинета.
type Config struct {
	// PublicURL — внешний адрес сервиса без завершающего слэша.
	PublicURL string
	// ResourceURL — адрес MCP, который пользователь вставляет в Claude.
	ResourceURL string
	// Registration — кто может зарегистрироваться.
	Registration Registration
	// ClientIP — как узнать адрес клиента (за обратным прокси).
	ClientIP func(*http.Request) string
	Logger   *slog.Logger
}

// Web — обработчик страниц и источник пользователей для OAuth.
type Web struct {
	db     *pgstore.DB
	boxes  *mailboxes.Service
	cfg    Config
	logger *slog.Logger

	secureCookie bool
	origin       string
	limiter      *ipLimiter
	mux          *http.ServeMux
}

// SessionTTL — сколько живёт вход в кабинет.
const SessionTTL = 30 * 24 * time.Hour

const sessionCookie = "emc_session"

// New собирает кабинет.
func New(db *pgstore.DB, boxSvc *mailboxes.Service, cfg Config) (*Web, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("web: MAIL_PUBLIC_URL должен быть полным адресом, например https://mail-mcp.example.com")
	}
	cfg.PublicURL = strings.TrimSuffix(cfg.PublicURL, "/")
	if cfg.ResourceURL == "" {
		cfg.ResourceURL = cfg.PublicURL + "/mcp"
	}
	if cfg.ClientIP == nil {
		cfg.ClientIP = func(r *http.Request) string { return r.RemoteAddr }
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	w := &Web{
		db:     db,
		boxes:  boxSvc,
		cfg:    cfg,
		logger: logger,
		// Cookie с флагом Secure браузер не вернёт по http. Локальная
		// отладка на http://localhost без этого не залогинилась бы.
		secureCookie: u.Scheme == "https",
		origin:       u.Scheme + "://" + u.Host,
		// 10 попыток входа или регистрации подряд, дальше одна в 30 с.
		// PBKDF2 намеренно дорог, и без ограничения форма входа —
		// готовый способ загрузить процессор сервера.
		limiter: newIPLimiter(10, 30*time.Second),
	}
	w.routes()
	return w, nil
}

// ServeHTTP обслуживает страницы.
func (w *Web) ServeHTTP(rw http.ResponseWriter, r *http.Request) { w.mux.ServeHTTP(rw, r) }

func (w *Web) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", w.landing)
	m.HandleFunc("GET /signup", w.signupForm)
	m.HandleFunc("POST /signup", w.sameOrigin(w.signup))
	m.HandleFunc("GET /login", w.loginForm)
	m.HandleFunc("POST /login", w.sameOrigin(w.login))
	m.HandleFunc("POST /logout", w.authed(w.logout))

	m.HandleFunc("GET /account", w.authed(w.account))
	m.HandleFunc("GET /account/mailboxes/new", w.authed(w.mailboxForm))
	m.HandleFunc("POST /account/mailboxes/new", w.authed(w.mailboxAdd))
	m.HandleFunc("GET /account/mailboxes/{id}/edit", w.authed(w.mailboxEditForm))
	m.HandleFunc("POST /account/mailboxes/{id}/edit", w.authed(w.mailboxEdit))
	m.HandleFunc("POST /account/mailboxes/{id}/check", w.authed(w.mailboxCheck))
	m.HandleFunc("POST /account/mailboxes/{id}/delete", w.authed(w.mailboxDelete))
	m.HandleFunc("POST /account/grants/{id}/revoke", w.authed(w.grantRevoke))
	m.HandleFunc("POST /account/tokens", w.authed(w.tokenCreate))
	m.HandleFunc("POST /account/tokens/{id}/delete", w.authed(w.tokenDelete))
	m.HandleFunc("POST /account/password", w.authed(w.passwordChange))
	m.HandleFunc("POST /account/delete", w.authed(w.accountDelete))
	m.HandleFunc("/", w.notFound)
	w.mux = m
}

// --- oauth.Accounts ---

var _ oauth.Accounts = (*Web)(nil)

// CurrentUser — кто вошёл в этом браузере.
func (w *Web) CurrentUser(r *http.Request) (oauth.User, bool) {
	s, _, ok := w.session(r)
	if !ok {
		return oauth.User{}, false
	}
	return oauth.User{ID: s.UserID, Email: s.Email}, true
}

// Mailboxes — ящики пользователя для экрана согласия.
func (w *Web) Mailboxes(ctx context.Context, userID int64) ([]oauth.Mailbox, error) {
	list, err := w.db.Mailboxes(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]oauth.Mailbox, 0, len(list))
	for _, m := range list {
		out = append(out, oauth.Mailbox{ID: m.ID, Name: m.Name, Email: m.Email})
	}
	return out, nil
}

// LoginURL — вход с возвратом на next.
func (w *Web) LoginURL(next string) string { return "/login?next=" + url.QueryEscape(next) }

// AddMailboxURL — подключение ящика с возвратом на next.
func (w *Web) AddMailboxURL(next string) string {
	return "/account/mailboxes/new?next=" + url.QueryEscape(next)
}

// Registration — режим регистрации.
type Registration string

const (
	// RegistrationOpen — регистрируется кто угодно.
	RegistrationOpen Registration = "open"
	// RegistrationInvite — только с кодом приглашения.
	RegistrationInvite Registration = "invite"
	// RegistrationClosed — новые учётные записи не создаются.
	RegistrationClosed Registration = "closed"
)

// ParseRegistration разбирает MAIL_REGISTRATION. Пусто — open.
func ParseRegistration(s string) (Registration, error) {
	switch Registration(strings.ToLower(strings.TrimSpace(s))) {
	case "", RegistrationOpen:
		return RegistrationOpen, nil
	case RegistrationInvite:
		return RegistrationInvite, nil
	case RegistrationClosed:
		return RegistrationClosed, nil
	}
	return "", errors.New("MAIL_REGISTRATION: допустимо open, invite или closed, получено " + s)
}

// --- сессии ---

// session читает сессию кабинета из cookie. Второе значение — хеш
// cookie (нужен, чтобы закрыть именно эту сессию).
func (w *Web) session(r *http.Request) (pgstore.WebSession, string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" || len(c.Value) > 100 {
		return pgstore.WebSession{}, "", false
	}
	h := secure.HashToken(c.Value)
	s, err := w.db.WebSession(r.Context(), h)
	if err != nil {
		if !errors.Is(err, pgstore.ErrNotFound) {
			w.logger.Error("чтение сессии", "err", err)
		}
		return pgstore.WebSession{}, "", false
	}
	return s, h, true
}

func (w *Web) startSession(rw http.ResponseWriter, r *http.Request, userID int64) error {
	token, err := secure.RandomToken()
	if err != nil {
		return err
	}
	csrf, err := secure.RandomToken()
	if err != nil {
		return err
	}
	if err := w.db.CreateWebSession(r.Context(), secure.HashToken(token), userID, csrf,
		time.Now().Add(SessionTTL)); err != nil {
		return err
	}
	_ = w.db.TouchLogin(r.Context(), userID)
	http.SetCookie(rw, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   w.secureCookie,
		// Lax, а не Strict: вход в OAuth начинается переходом с
		// claude.ai, и со Strict браузер не прислал бы cookie —
		// человек, только что вошедший, увидел бы форму входа снова.
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (w *Web) clearCookie(rw http.ResponseWriter) {
	http.SetCookie(rw, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: w.secureCookie, SameSite: http.SameSiteLaxMode,
	})
}

// request — запрос вошедшего пользователя.
type request struct {
	*http.Request
	sess     pgstore.WebSession
	sessHash string
}

// authed пускает только вошедших; POST дополнительно сверяет CSRF.
func (w *Web) authed(h func(http.ResponseWriter, *request)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		s, hash, ok := w.session(r)
		if !ok {
			if r.Method == http.MethodGet {
				http.Redirect(rw, r, w.LoginURL(r.URL.RequestURI()), http.StatusFound)
				return
			}
			w.message(rw, http.StatusUnauthorized, "Нужно войти", "Сессия истекла — войдите заново.")
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(rw, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				w.message(rw, http.StatusBadRequest, "Не разобрана форма", err.Error())
				return
			}
			// Токен формы сверяется с сессией: сайт-злоумышленник может
			// заставить браузер отправить форму, но не может прочитать
			// токен со страницы кабинета.
			if !secureEqual(r.PostFormValue("csrf"), s.CSRF) {
				w.message(rw, http.StatusForbidden, "Форма устарела",
					"Обновите страницу и повторите действие.")
				return
			}
		}
		h(rw, &request{Request: r, sess: s, sessHash: hash})
	}
}

// sameOrigin — защита анонимных форм (вход, регистрация): браузер
// присылает Origin на POST, и чужой сайт отправить их не сможет.
func (w *Web) sameOrigin(h http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && o != "null" && !strings.EqualFold(o, w.origin) {
			w.message(rw, http.StatusForbidden, "Чужой источник", "Форма отправлена не с этого сайта.")
			return
		}
		r.Body = http.MaxBytesReader(rw, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			w.message(rw, http.StatusBadRequest, "Не разобрана форма", err.Error())
			return
		}
		if !w.limiter.allow(w.cfg.ClientIP(r)) {
			w.message(rw, http.StatusTooManyRequests, "Слишком много попыток",
				"Подождите минуту и попробуйте снова.")
			return
		}
		h(rw, r)
	}
}

// safeNext оставляет только адреса этого же сайта: иначе форма входа
// превращается в открытый редирект для фишинга.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") ||
		strings.HasPrefix(next, "/\\") || strings.ContainsAny(next, "\r\n") {
		return "/account"
	}
	return next
}
