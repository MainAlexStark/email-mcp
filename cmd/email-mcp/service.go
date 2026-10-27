package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/MainAlexStark/email-mcp/internal/files"
	"github.com/MainAlexStark/email-mcp/internal/httpx"
	"github.com/MainAlexStark/email-mcp/internal/mailboxes"
	"github.com/MainAlexStark/email-mcp/internal/oauth"
	"github.com/MainAlexStark/email-mcp/internal/pgstore"
	"github.com/MainAlexStark/email-mcp/internal/secure"
	"github.com/MainAlexStark/email-mcp/internal/tools"
	"github.com/MainAlexStark/email-mcp/internal/web"
	"github.com/MainAlexStark/email-mcp/mail"
)

// runService — многопользовательский сервис.
func runService(ctx context.Context, safety tools.Safety, addr string) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	publicURL := strings.TrimSuffix(os.Getenv("MAIL_PUBLIC_URL"), "/")
	if publicURL == "" {
		fatal("сервису нужен MAIL_PUBLIC_URL — внешний адрес, например https://mail-mcp.example.com")
	}
	if accs, _ := envAccounts(); len(accs) > 0 {
		// Ящики из окружения — конфигурация stdio. В сервисе ящики у
		// пользователей, и такие переменные почти наверняка остались от
		// локальной настройки и молча ни на что не влияют.
		logger.Warn("MAIL_IMAP_<ID>_* в сервисном режиме не используются: " +
			"зарегистрируйтесь в кабинете и подключите ящик там")
	}
	registration, err := web.ParseRegistration(os.Getenv("MAIL_REGISTRATION"))
	if err != nil {
		fatal(err.Error())
	}

	cipher, err := secure.NewCipher(os.Getenv("MAIL_SECRET_KEY"))
	if err != nil {
		fatal(err.Error())
	}

	db := openDB(ctx)
	defer db.Close()

	// Адрес почтового сервера вводит пользователь. Без запрета внутренних
	// адресов проверка ящика стала бы сканером сети, в которой стоит
	// сервис (база, метаданные облака). Свой почтовый сервер в той же
	// сети открывается явно.
	var opts []mail.Option
	private := envBool("MAIL_ALLOW_PRIVATE_HOSTS")
	if !private {
		opts = append(opts, mail.WithPublicOnly())
	}
	if o, err := proxyOption(); err != nil {
		fatal(err.Error())
	} else if o != nil {
		opts = append(opts, o)
	}
	boxSvc := mailboxes.New(db, cipher, opts...)
	boxSvc.AllowPlaintext = private

	resourceURL := os.Getenv("MAIL_RESOURCE_URL")

	site, err := web.New(db, boxSvc, web.Config{
		PublicURL:    publicURL,
		ResourceURL:  resourceURL,
		Registration: registration,
		ClientIP:     httpx.ClientIP,
		Logger:       logger,
	})
	if err != nil {
		fatal(err.Error())
	}

	oauthSrv, err := oauth.New(oauth.Config{
		Issuer:      publicURL,
		ResourceURL: resourceURL,
		Store:       db.OAuth(),
		Accounts:    site,
		Logger:      logger,
	})
	if err != nil {
		fatal(err.Error())
	}

	apiTokens := func(ctx context.Context, token string) (httpx.Principal, bool) {
		t, err := db.APITokenByHash(ctx, secure.HashToken(token))
		if err != nil {
			if !errors.Is(err, pgstore.ErrNotFound) {
				logger.Error("проверка API-токена", "err", err)
			}
			return httpx.Principal{}, false
		}
		return httpx.Principal{UserID: t.UserID, MailboxID: t.MailboxID,
			Grants: httpx.GrantsFromScopes(t.Scopes)}, true
	}

	usage := newUsageRecorder(ctx, db, logger)

	var origins []string
	for _, o := range strings.Split(os.Getenv("MAIL_ALLOWED_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}

	// Вложения в сервисе живут в памяти и отдаются по ссылке: диска
	// пользователя у сервера нет, а хранить чужие письма дольше, чем
	// нужно, чтобы их скачать, незачем.
	fileStore := files.NewMemory(publicURL, envDuration("MAIL_FILES_TTL", time.Hour), 256<<20)

	srv := newMCP(tools.Config{Files: fileStore, MailOptions: boxSvc.Options()}, safety)
	http, err := httpx.NewServer(srv,
		httpx.Auth{OAuth: oauthSrv, APITokens: apiTokens},
		boxSvc,
		usage,
		httpx.Config{
			Addr:           addr,
			AllowedOrigins: origins,
			Safety:         safety,
			Web:            site,
			Files:          fileStore,
			Ready:          db.Ping,
			Logger:         logger,
		})
	if err != nil {
		fatal(err.Error())
	}

	go cleanupLoop(ctx, db, logger)

	logger.Info("сервис запущен",
		"version", version,
		"addr", addr,
		"public", publicURL,
		"resource", oauthSrv.ResourceURL(),
		"tools", len(srv.ToolNames()),
		"registration", registration)

	if err := http.ListenAndServe(ctx); err != nil {
		fatal(err.Error())
	}
}

// openDB подключается к базе и применяет миграции. Миграции на старте,
// а не отдельным шагом: забытый шаг развёртывания выглядел бы как
// «сервер падает на первом запросе», а не как внятная ошибка.
func openDB(ctx context.Context) *pgstore.DB {
	url := os.Getenv("MAIL_DATABASE_URL")
	if url == "" {
		fatal("нужен MAIL_DATABASE_URL, например postgres://mail:пароль@postgres:5432/mail")
	}
	var (
		db  *pgstore.DB
		err error
	)
	// База в compose может подниматься дольше сервера: ждём до минуты,
	// прежде чем сдаться.
	for i := 0; i < 20; i++ {
		db, err = pgstore.Open(ctx, url)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			fatal(ctx.Err().Error())
		case <-time.After(3 * time.Second):
		}
	}
	if err != nil {
		fatal("база: " + err.Error())
	}
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		fatal(err.Error())
	}
	return db
}

// cleanupLoop раз в час убирает истёкшие сессии, коды и токены.
func cleanupLoop(ctx context.Context, db *pgstore.DB, logger *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if err := db.Cleanup(ctx); err != nil && ctx.Err() == nil {
			logger.Warn("чистка базы", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type usageEvent struct {
	user, mailbox int64
	tool          string
	failed        bool
}

// newUsageRecorder пишет учёт вызовов в фоне: запись в базу не должна
// задерживать ответ инструмента. Если очередь переполнена (база
// тормозит), событие теряется — учёт не стоит того, чтобы из-за него
// вставал сервис.
func newUsageRecorder(ctx context.Context, db *pgstore.DB, logger *slog.Logger) httpx.UsageFunc {
	ch := make(chan usageEvent, 1000)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case e := <-ch:
				wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := db.RecordUsage(wctx, e.user, e.mailbox, e.tool, e.failed); err != nil {
					logger.Warn("учёт вызова", "err", err)
				}
				cancel()
			}
		}
	}()
	return func(user, mailbox int64, tool string, failed bool) {
		select {
		case ch <- usageEvent{user, mailbox, tool, failed}:
		default:
			logger.Warn("очередь учёта переполнена, вызов не учтён", "tool", tool)
		}
	}
}
