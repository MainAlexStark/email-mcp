// Package oauth — встроенный сервер авторизации OAuth 2.1 для MCP.
//
// Зачем он здесь. Раньше доступ закрывался длинным секретом в адресе:
// это работало везде, включая мобильное приложение, но имело три изъяна,
// которые нельзя починить, не сменив схему.
//
//  1. Спецификация MCP прямо запрещает передавать токен в строке запроса:
//     адреса попадают в журналы серверов, прокси и историю браузера.
//  2. Отозвать доступ можно было только сменой секрета — то есть сразу
//     у всех устройств.
//  3. Секрет жил вечно: утёкший однажды оставался годным.
//
// OAuth снимает все три: токены живут час, обновляются по refresh,
// отзываются поштучно, а согласие даётся на конкретный набор прав.
//
// Сервер играет обе роли сразу — и resource server, и authorization
// server. Пользователей и их ящики он не хранит сам: кто вошёл
// и какие у него ящики, сообщает веб-кабинет через Accounts.
// Экран согласия — это «под какой учётной записью, к каким ящикам
// и с какими правами подключить это приложение».
package oauth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Области доступа.
//
// Четыре права вместо привычных read/write: у почты три разных вида
// риска. Черновик никуда не уходит, изменение ящика (перенос, удаление)
// обратимо не всегда, отправку не вернуть вовсе. Человек отмечает их
// по отдельности, подключая, например, телефон только на чтение.
const (
	ScopeRead   = "mail:read"
	ScopeDrafts = "mail:drafts"
	ScopeWrite  = "mail:write"
	ScopeSend   = "mail:send"

	// ScopeOfflineAccess запрашивается Claude, чтобы получить refresh.
	// Без него доступ пришлось бы подтверждать заново каждый час.
	ScopeOfflineAccess = "offline_access"
)

// MailScopes — права почты в порядке возрастания риска.
var MailScopes = []string{ScopeRead, ScopeDrafts, ScopeWrite, ScopeSend}

// Времена жизни.
const (
	// AccessTokenTTL намеренно короткий: утёкший токен протухнет сам.
	AccessTokenTTL = time.Hour
	// RefreshTokenTTL — сколько устройство может не появляться,
	// прежде чем придётся подтверждать доступ заново.
	RefreshTokenTTL = 30 * 24 * time.Hour
	// AuthCodeTTL — код обменивается сразу, держать его долго незачем.
	AuthCodeTTL = 5 * time.Minute
	// LoginSessionTTL — сколько даётся на прохождение формы согласия.
	LoginSessionTTL = 15 * time.Minute
)

// Accounts — сведения о пользователях, которые даёт веб-кабинет.
type Accounts interface {
	// CurrentUser — кто вошёл в этом браузере (по cookie кабинета).
	CurrentUser(r *http.Request) (User, bool)
	// Mailboxes — ящики пользователя для экрана согласия.
	Mailboxes(ctx context.Context, userID int64) ([]Mailbox, error)
	// LoginURL — страница входа, после которой вернуться на next.
	LoginURL(next string) string
	// AddMailboxURL — страница подключения ящика с возвратом на next.
	AddMailboxURL(next string) string
}

// User — вошедший пользователь.
type User struct {
	ID    int64
	Email string
}

// Mailbox — ящик пользователя, как он показывается на согласии.
type Mailbox struct {
	ID    int64
	Name  string
	Email string
}

// Config — настройки сервера авторизации.
type Config struct {
	// Issuer — внешний адрес сервера без завершающего слэша,
	// например https://mail-mcp.example.com. Он же используется как
	// issuer и как основа для всех эндпоинтов.
	Issuer string

	// ResourceURL — канонический адрес MCP-эндпоинта, каким его вводит
	// пользователь в Claude. Должен совпадать с ним в точности:
	// по этому значению Claude сверяет метаданные, и расхождение
	// в один слэш ломает подключение.
	ResourceURL string

	Store    Storage
	Accounts Accounts
	Logger   *slog.Logger
}

// Server — сервер авторизации.
type Server struct {
	cfg      Config
	store    Storage
	accounts Accounts
	logger   *slog.Logger
}

// New создаёт сервер авторизации.
func New(cfg Config) (*Server, error) {
	if cfg.Issuer == "" {
		return nil, errConfig("не задан внешний адрес сервера (MAIL_PUBLIC_URL)")
	}
	if cfg.Store == nil {
		return nil, errConfig("не задано хранилище")
	}
	if cfg.Accounts == nil {
		return nil, errConfig("не задан источник пользователей")
	}

	cfg.Issuer = strings.TrimSuffix(cfg.Issuer, "/")
	if cfg.ResourceURL == "" {
		cfg.ResourceURL = cfg.Issuer + "/mcp"
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Server{cfg: cfg, store: cfg.Store, accounts: cfg.Accounts, logger: logger}, nil
}

// Issuer возвращает адрес издателя токенов.
func (s *Server) Issuer() string { return s.cfg.Issuer }

// ResourceURL возвращает канонический адрес защищаемого ресурса.
func (s *Server) ResourceURL() string { return s.cfg.ResourceURL }

// Mount регистрирует эндпоинты авторизации.
//
// Пути well-known дублируются с суффиксом пути ресурса: Claude сначала
// пробует /.well-known/oauth-protected-resource/mcp и лишь потом
// корневой вариант.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.protectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/{path...}", s.protectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.authorizationServerMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/{path...}", s.authorizationServerMetadata)

	mux.HandleFunc("POST /oauth/register", s.handleRegister)
	mux.HandleFunc("GET /oauth/authorize", s.handleAuthorize)
	mux.HandleFunc("POST /oauth/authorize", s.handleAuthorizeSubmit)
	mux.HandleFunc("POST /oauth/token", s.handleToken)
	mux.HandleFunc("POST /oauth/revoke", s.handleRevoke)
}

type configError struct{ msg string }

func errConfig(msg string) error     { return &configError{msg: msg} }
func (e *configError) Error() string { return "oauth: " + e.msg }
