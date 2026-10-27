// Команда email-mcp — MCP-сервер почты: IMAP для чтения, SMTP для отправки.
//
// Два режима:
//
//   - stdio (по умолчанию) — Claude запускает сервер как подпроцесс на
//     той же машине. Ящики и права — из окружения, в формате исходного
//     mail-mcp (tecnologicachile/mail-mcp).
//
//   - сервис (--http) — многопользовательский сервер: регистрация,
//     кабинет, ящики пользователей в PostgreSQL (пароли зашифрованы),
//     OAuth для Claude. Каждое подключение — все ящики пользователя или
//     один, с правами, отмеченными на экране согласия.
//
// Переменные окружения, stdio:
//
//	MAIL_IMAP_<ID>_HOST, _PORT, _SECURE, _USER, _PASS   ящик <ID> (обязательно хоть один)
//	MAIL_SMTP_<ID>_HOST, _PORT, _SECURE, _USER, _PASS   отправка с ящика <ID>
//	MAIL_SMTP_<ID>_FROM_EMAIL, _FROM_NAME, _SAVE_SENT    адрес и имя отправителя, копия в «Отправленные»
//	MAIL_ALLOW_DRAFTS        true — черновики (старое имя: MAIL_DRAFTS_ENABLED)
//	MAIL_ALLOW_WRITES        true — изменение ящика (старое имя: MAIL_IMAP_WRITE_ENABLED)
//	MAIL_ALLOW_SEND          true — отправка (старое имя: MAIL_SMTP_WRITE_ENABLED)
//	MAIL_ATTACHMENT_DOWNLOAD_DIR  куда сохранять вложения (по умолчанию «Загрузки/email-mcp»)
//	MAIL_ATTACHMENT_UPLOAD_DIR    откуда можно брать file_path для исходящих вложений
//
// Переменные окружения, сервис:
//
//	MAIL_DATABASE_URL        обязательно: postgres://user:pass@host:5432/db
//	MAIL_SECRET_KEY          обязательно: мастер-ключ шифрования паролей ящиков (--gen-secret)
//	MAIL_PUBLIC_URL          обязательно: внешний адрес, https://mail-mcp.example.com
//	MAIL_HTTP_ADDR           адрес прослушивания, если не задан --http
//	MAIL_RESOURCE_URL        адрес MCP, если отличается от <public>/mcp
//	MAIL_REGISTRATION        open (по умолчанию), invite или closed
//	MAIL_ALLOWED_ORIGINS     разрешённые Origin для /mcp через запятую
//	MAIL_FILES_TTL           сколько живёт ссылка на вложение (1h)
//	MAIL_ALLOW_PRIVATE_HOSTS true — разрешить ящики на внутренних адресах (свой почтовый сервер в той же сети)
//
// Общие:
//
//	MAIL_MAX_ITEMS_PER_WRITE писем за одну операцию изменения (100)
//	MAIL_MAX_RECIPIENTS      получателей без confirm_many_recipients (10)
//	MAIL_MAX_RESPONSE_BYTES  потолок размера ответа (40000)
//	MAIL_PROXY               socks5://[user:pass@]host:port — IMAP/SMTP через прокси (Gmail из России)
//	MAIL_TIMEOUT             потолок одной операции с почтовым сервером (2m)
//	MAIL_IMAP_SEARCH_CONCURRENCY  соединений на поиск по всем папкам (4, 1–8)
//	MAIL_IMAP_MAX_MAILBOXES  потолок списка папок (200)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MainAlexStark/email-mcp/internal/files"
	"github.com/MainAlexStark/email-mcp/internal/mcp"
	"github.com/MainAlexStark/email-mcp/internal/tools"
	"github.com/MainAlexStark/email-mcp/mail"
)

// version подменяется при сборке: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	var (
		httpAddr    = flag.String("http", "", "поднять сервис на указанном адресе, например :8572")
		check       = flag.Bool("check", false, "проверить ящики из окружения и выйти")
		genSecret   = flag.Bool("gen-secret", false, "сгенерировать MAIL_SECRET_KEY")
		migrate     = flag.Bool("migrate", false, "применить миграции базы и выйти")
		users       = flag.Bool("users", false, "показать пользователей сервиса")
		disable     = flag.String("disable", "", "заблокировать пользователя по почте")
		enable      = flag.String("enable", "", "разблокировать пользователя по почте")
		setPassword = flag.String("set-password", "", "задать пароль пользователю (пароль читается со stdin)")
		invite      = flag.Int("invite", 0, "выпустить N приглашений для MAIL_REGISTRATION=invite")
		inviteNote  = flag.String("invite-note", "", "пометка к приглашениям: кому выдаются")
		inviteTTL   = flag.Duration("invite-ttl", 14*24*time.Hour, "срок действия приглашений, 0 — бессрочно")
		invites     = flag.Bool("invites", false, "показать приглашения")
		showVersion = flag.Bool("version", false, "показать версию")
	)
	flag.Parse()

	switch {
	case *showVersion:
		fmt.Println("email-mcp", version)
		return
	case *genSecret:
		printSecretKey()
		return
	case *migrate:
		runMigrate()
		return
	case *users:
		listUsers()
		return
	case *disable != "":
		setDisabled(*disable, true)
		return
	case *enable != "":
		setDisabled(*enable, false)
		return
	case *setPassword != "":
		resetPassword(*setPassword)
		return
	case *invite > 0:
		createInvites(*invite, *inviteNote, *inviteTTL)
		return
	case *invites:
		listInvites()
		return
	}

	safety := tools.DefaultSafety()
	safety.MaxItemsPerWrite = envInt("MAIL_MAX_ITEMS_PER_WRITE", safety.MaxItemsPerWrite)
	safety.MaxRecipients = envInt("MAIL_MAX_RECIPIENTS", safety.MaxRecipients)
	safety.MaxResponseBytes = envInt("MAIL_MAX_RESPONSE_BYTES", safety.MaxResponseBytes)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr := *httpAddr
	if addr == "" {
		addr = os.Getenv("MAIL_HTTP_ADDR")
	}
	if addr != "" {
		runService(ctx, safety, addr)
		return
	}

	accounts, err := envAccounts()
	if err != nil {
		fatal(err.Error())
	}
	if len(accounts) == 0 {
		fatal("не задан ни один ящик. Минимум:\n" +
			"  MAIL_IMAP_DEFAULT_HOST=imap.example.com\n" +
			"  MAIL_IMAP_DEFAULT_USER=you@example.com\n" +
			"  MAIL_IMAP_DEFAULT_PASS=пароль-приложения\n" +
			"Адреса серверов известных провайдеров — в docs/PROVIDERS.md.")
	}

	// В stdio права — свойство процесса: сервер запускает сам владелец
	// на своей машине.
	safety.Drafts = envBool("MAIL_ALLOW_DRAFTS", "MAIL_DRAFTS_ENABLED")
	safety.Write = envBool("MAIL_ALLOW_WRITES", "MAIL_IMAP_WRITE_ENABLED")
	safety.Send = envBool("MAIL_ALLOW_SEND", "MAIL_SMTP_WRITE_ENABLED")

	mailOpts := []mail.Option(nil)
	if o, err := proxyOption(); err != nil {
		fatal(err.Error())
	} else if o != nil {
		mailOpts = append(mailOpts, o)
	}

	srv := newMCP(tools.Config{
		Accounts:    accounts,
		MailOptions: mailOpts,
		Files:       stdioFiles(),
		UploadDir:   os.Getenv("MAIL_ATTACHMENT_UPLOAD_DIR"),
	}, safety)

	if *check {
		runCheck(accounts, srv, safety)
		return
	}
	runStdio(ctx, srv, safety)
}

// stdioFiles — папка для вложений в локальном режиме.
func stdioFiles() files.Store {
	dir := os.Getenv("MAIL_ATTACHMENT_DOWNLOAD_DIR")
	if dir == "" {
		dir = files.DefaultDir()
	}
	store, err := files.NewDir(dir)
	if err != nil {
		fatal(err.Error())
	}
	return store
}

// newMCP собирает сервер со всеми инструментами.
func newMCP(cfg tools.Config, safety tools.Safety) *mcp.Server {
	cfg.SearchConcurrency = envInt("MAIL_IMAP_SEARCH_CONCURRENCY", 4)
	cfg.MaxMailboxes = envInt("MAIL_IMAP_MAX_MAILBOXES", 200)
	srv := mcp.NewServer("email-mcp", version)
	tools.RegisterAll(tools.NewRegistry(cfg, safety, srv))
	return srv
}

// runStdio — локальный режим: Claude запускает сервер подпроцессом.
func runStdio(ctx context.Context, srv *mcp.Server, safety tools.Safety) {
	// Диагностика уходит в stderr: stdout занят протоколом.
	fmt.Fprintf(os.Stderr, "email-mcp %s: stdio, %d инструментов, права: %s\n",
		version, len(srv.ToolNames()), safety.Mode())
	if err := srv.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		fatal(err.Error())
	}
}

// runCheck проверяет ящики до того, как сервер пропишут в Claude:
// отлаживать молчащий MCP внутри клиента дольше, чем прочитать этот вывод.
func runCheck(accounts []mail.Account, srv *mcp.Server, safety tools.Safety) {
	fmt.Printf("email-mcp %s\n", version)
	fmt.Printf("Инструментов: %d\n", len(srv.ToolNames()))
	fmt.Printf("Права:        %s\n\n", safety.Mode())

	failed := false
	for _, acc := range accounts {
		fmt.Printf("%s (%s)\n", acc.ID, acc.Sender())
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		var mopts []mail.Option
		if o, err := proxyOption(); err != nil {
			fatal(err.Error())
		} else if o != nil {
			mopts = append(mopts, o)
		}
		c := mail.New(acc, mopts...)
		if res, err := c.VerifyIMAP(ctx); err != nil {
			failed = true
			fmt.Printf("  IMAP %s:%d — не прошло: %v\n", acc.IMAP.Host, acc.IMAP.Port, err)
			if h := mail.Hint(err); h != "" {
				fmt.Printf("  %s\n", h)
			}
		} else {
			fmt.Printf("  IMAP %s:%d — вход принят (%d мс)\n", acc.IMAP.Host, acc.IMAP.Port, res.LatencyMS)
		}
		if acc.SMTP.Configured() {
			if res, err := c.VerifySMTP(ctx); err != nil {
				failed = true
				fmt.Printf("  SMTP %s:%d — не прошло: %v\n", acc.SMTP.Host, acc.SMTP.Port, err)
				if h := mail.Hint(err); h != "" {
					fmt.Printf("  %s\n", h)
				}
			} else {
				fmt.Printf("  SMTP %s:%d — вход принят (%d мс)\n", acc.SMTP.Host, acc.SMTP.Port, res.LatencyMS)
			}
		} else {
			fmt.Println("  SMTP не настроен — отправка с этого ящика недоступна")
		}
		cancel()
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("\nСервер готов. Пропишите его в Claude как stdio-сервер;")
	fmt.Println("сервис для многих пользователей — см. docs/REMOTE.md.")
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "email-mcp:", msg)
	os.Exit(1)
}

// proxyOption читает MAIL_PROXY (socks5://[user:pass@]host:port).
// Пусто — прямое подключение. Неверный адрес — ошибка на старте:
// молча ходить напрямую, когда просили через прокси, хуже всего.
func proxyOption() (mail.Option, error) {
	raw := strings.TrimSpace(os.Getenv("MAIL_PROXY"))
	if raw == "" {
		return nil, nil
	}
	o, err := mail.WithProxy(raw)
	if err != nil {
		return nil, fmt.Errorf("MAIL_PROXY: %w", err)
	}
	return o, nil
}
