package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/MainAlexStark/email-mcp/internal/files"
	"github.com/MainAlexStark/email-mcp/internal/mcp"
	"github.com/MainAlexStark/email-mcp/internal/oauth"
	"github.com/MainAlexStark/email-mcp/internal/tools"
	"github.com/MainAlexStark/email-mcp/mail"
)

// Config — настройки сетевого транспорта.
type Config struct {
	Addr string

	// AllowedOrigins — источники, которым разрешено обращаться к /mcp
	// из браузера. Пусто означает «браузерные запросы с Origin
	// отклоняются», и для сервера, к которому ходит только Claude,
	// это правильное значение по умолчанию.
	AllowedOrigins []string

	// Safety — пороги защиты, общие для всех подключений. Режим
	// (чтение/запись) сюда не входит: он определяется токеном.
	Safety tools.Safety

	// Web — страницы сервиса (регистрация, кабинет). Обслуживает всё,
	// что не /mcp, не OAuth и не /healthz.
	Web http.Handler

	// Files — раздача сохранённых вложений по ссылкам /files/….
	// Без авторизации намеренно: ссылку открывает браузер человека,
	// у которого нет токена Claude, а доступ держится на неугадываемом
	// токене в самом пути и коротком сроке жизни.
	Files http.Handler

	// Ready — проверка готовности для /healthz (например, пинг базы).
	Ready func(ctx context.Context) error

	Logger *slog.Logger
}

// Mailboxes выдаёт ящики подключения: один или все ящики пользователя.
type Mailboxes interface {
	Accounts(ctx context.Context, userID, mailboxID int64) ([]mail.Account, error)
}

// UsageFunc узнаёт о каждом вызове инструмента.
type UsageFunc func(userID, mailboxID int64, tool string, failed bool)

// Auth — способы проверки входящих запросов.
//
// OAuth — основной: короткие токены, поштучный отзыв, согласие на
// конкретные ящики и права. Персональные токены — для автоматизации,
// которая не может пройти экран согласия.
type Auth struct {
	OAuth     *oauth.Server
	APITokens APITokenFunc
}

// Server — сетевая обвязка вокруг MCP: авторизация, ящики подключения,
// права и проверка Origin.
//
// Сам протокол обслуживает обработчик из internal/mcp, работающий без
// состояния: сервер не выдаёт Mcp-Session-Id и не требует его. Каждый
// запрос самодостаточен, поэтому переживает перезапуск процесса и не
// ломается за балансировщиком.
type Server struct {
	mcpHTTP http.Handler
	auth    Auth
	boxes   Mailboxes
	usage   UsageFunc
	cfg     Config
	logger  *slog.Logger
}

// maxRequestBytes — потолок размера тела запроса. Без него один запрос
// может съесть память сервера.
const maxRequestBytes = 8 << 20

// ErrNoAuth возвращается, когда сервер пытаются поднять без защиты.
var ErrNoAuth = errors.New("httpx: сетевой режим требует OAuth (MAIL_PUBLIC_URL) — см. docs/REMOTE.md")

// ErrNoMailboxes — не задан источник ящиков.
var ErrNoMailboxes = errors.New("httpx: не задан источник ящиков")

// NewServer собирает сетевой транспорт.
func NewServer(m *mcp.Server, auth Auth, boxes Mailboxes, usage UsageFunc, cfg Config) (*Server, error) {
	if auth.OAuth == nil && auth.APITokens == nil {
		return nil, ErrNoAuth
	}
	if boxes == nil {
		return nil, ErrNoMailboxes
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		mcpHTTP: m.StreamableHandler(mcp.StreamableOptions{
			Logger:          logger,
			MaxRequestBytes: maxRequestBytes,
		}),
		auth:   auth,
		boxes:  boxes,
		usage:  usage,
		cfg:    cfg,
		logger: logger,
	}, nil
}

// Handler возвращает HTTP-обработчик.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)

	// Эндпоинты авторизации регистрируются отдельно от /mcp, иначе они
	// попали бы под проверку токена — которого у клиента на этом этапе
	// ещё нет.
	if s.auth.OAuth != nil {
		s.auth.OAuth.Mount(mux)
	}

	if s.cfg.Files != nil {
		mux.Handle(files.Prefix, s.cfg.Files)
	}

	mux.HandleFunc("/mcp", s.mcpEndpoint)
	mux.HandleFunc("/mcp/", s.mcpEndpoint)

	if s.cfg.Web != nil {
		mux.Handle("/", s.cfg.Web)
	}
	return mux
}

// ListenAndServe поднимает сервер.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      6 * time.Minute, // поиск по всем папкам большого ящика идёт минутами
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}

// health отвечает без авторизации: он ничего не рассказывает о
// ящиках и нужен, чтобы обратный прокси и мониторинг видели
// живость процесса. Без базы сервис бесполезен, поэтому она тоже
// проверяется.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.cfg.Ready != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := s.cfg.Ready(ctx); err != nil {
			s.logger.Error("healthz: не готов", "err", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"status":"unavailable"}`)
			return
		}
	}
	fmt.Fprint(w, `{"status":"ok"}`)
}

func (s *Server) mcpEndpoint(w http.ResponseWriter, r *http.Request) {
	// Защита от DNS rebinding: браузер на постороннем сайте не должен
	// уметь обращаться к серверу от имени пользователя.
	if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(origin) {
		s.logger.Warn("отклонён запрос с чужого Origin", "origin", origin)
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}

	p, ok := s.authorize(w, r)
	if !ok {
		return // ответ уже отправлен
	}

	// Ящики подключения. Удалённый ящик (или токен к нему, чудом
	// переживший каскадное удаление) — это 403, а не 401: на 401
	// клиент побежит обновлять токен и зациклится.
	accounts, err := s.boxes.Accounts(r.Context(), p.UserID, p.MailboxID)
	if err != nil {
		s.logger.Warn("ящики подключения недоступны",
			"user", p.UserID, "mailbox", p.MailboxID, "err", err)
		writeForbidden(w, "ящик этого подключения удалён или недоступен — подключите сервер в Claude заново")
		return
	}

	// Права и ящики кладём в контекст: инструменты читают именно
	// оттуда, а не из настроек процесса. Обработчик протокола передаёт
	// контекст запроса дальше, до вызова инструмента, поэтому подмена
	// по дороге невозможна. Из настроек процесса берутся только пороги:
	// все разрешения сброшены и выставляются по токену.
	safety := s.cfg.Safety
	safety.Drafts, safety.Write, safety.Send = p.Grants.Drafts, p.Grants.Write, p.Grants.Send
	ctx := tools.WithSafety(r.Context(), safety)
	ctx = tools.WithAccounts(ctx, accounts)
	if s.usage != nil {
		userID, mailboxID := p.UserID, p.MailboxID
		ctx = tools.WithCallHook(ctx, func(tool string, failed bool) {
			s.usage(userID, mailboxID, tool, failed)
		})
	}

	// Тело не логируем: в нём бывают чувствительные данные.
	s.logger.Info("запрос",
		"http", r.Method,
		"user", p.UserID,
		"mailbox", p.MailboxID,
		"grants", p.Grants.String(),
		"via", p.Via,
		"remote", clientIP(r))

	s.mcpHTTP.ServeHTTP(w, r.WithContext(ctx))
}

// authorize определяет, чей это запрос.
//
// При отказе ответ обязан быть 401 с заголовком WWW-Authenticate,
// указывающим на метаданные ресурса: именно по нему клиент понимает,
// куда идти за токеном. Без этого заголовка Claude просто не узнает,
// что сервер вообще поддерживает OAuth, и подключение молча не
// состоится.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	token := bearerToken(r)

	if token != "" {
		if strings.HasPrefix(token, APITokenPrefix) {
			if s.auth.APITokens != nil {
				if p, ok := s.auth.APITokens(r.Context(), token); ok {
					p.Via = "api_token"
					return p, true
				}
			}
		} else if s.auth.OAuth != nil {
			if t, err := s.auth.OAuth.Validate(r.Context(), token); err == nil {
				return Principal{UserID: t.UserID, MailboxID: t.MailboxID,
					Grants: GrantsFromScopes(t.Scopes), Via: "oauth"}, true
			}
		}
	}

	// Тело и адрес не логируем: в них могут быть чувствительные данные.
	s.logger.Warn("отказ в доступе", "remote", clientIP(r), "method", r.Method)

	if s.auth.OAuth != nil {
		desc := "требуется авторизация"
		if token != "" {
			desc = "токен недействителен или истёк"
		}
		s.auth.OAuth.WriteUnauthorized(w, desc)
		return Principal{}, false
	}

	w.Header().Set("WWW-Authenticate", `Bearer realm="email-mcp"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return Principal{}, false
}

func writeForbidden(w http.ResponseWriter, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `{"error":"forbidden","error_description":%q}`, desc)
}

func (s *Server) originAllowed(origin string) bool {
	for _, allowed := range s.cfg.AllowedOrigins {
		if strings.EqualFold(strings.TrimSpace(allowed), origin) {
			return true
		}
	}
	return false
}

// clientIP берёт адрес из X-Forwarded-For, если сервер стоит за прокси.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	return r.RemoteAddr
}

// ClientIP — адрес клиента для журналов и ограничения частоты.
func ClientIP(r *http.Request) string { return clientIP(r) }
