package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/MainAlexStark/email-mcp/internal/files"
	"github.com/MainAlexStark/email-mcp/internal/mcp"
	"github.com/MainAlexStark/email-mcp/mail"
)

// Config — то, что реестр знает о режиме работы.
type Config struct {
	// Accounts — ящики stdio-режима. В сервисе nil: ящики приходят
	// из контекста запроса.
	Accounts []mail.Account

	// MailOptions — настройки клиентов ящиков (в сервисе — запрет
	// внутренних адресов).
	MailOptions []mail.Option

	// Files — куда класть вложения, которые просит модель. nil —
	// сохранять некуда, и imap_get_attachment отдаёт только base64.
	Files files.Store

	// UploadDir — откуда разрешено брать file_path для исходящих
	// вложений (stdio). Пусто — file_path запрещён: в сервисе диск
	// сервера не принадлежит пользователю, а локально модель, попавшая
	// под prompt injection, отправила бы ~/.ssh/id_rsa вложением.
	UploadDir string

	// SearchConcurrency — соединений на imap_search_all_mailboxes.
	SearchConcurrency int
	// MaxMailboxes — потолок списка папок.
	MaxMailboxes int
}

// Registry собирает инструменты и раздаёт им общий контекст.
type Registry struct {
	safety   Safety
	server   *mcp.Server
	accounts []mail.Account
	cfg      Config
}

// NewRegistry создаёт реестр.
func NewRegistry(cfg Config, safety Safety, server *mcp.Server) *Registry {
	if cfg.SearchConcurrency <= 0 {
		cfg.SearchConcurrency = 4
	}
	if cfg.MaxMailboxes <= 0 {
		cfg.MaxMailboxes = 200
	}
	return &Registry{safety: safety, server: server, accounts: cfg.Accounts, cfg: cfg}
}

// Spec — описание инструмента.
type Spec struct {
	Name string
	Desc string

	// Access — какое право нужно. Проверяется в Add и только там.
	Access Access

	// Schema — JSON Schema аргументов. Модель видит именно её.
	Schema map[string]any

	// Batch сообщает, сколько писем затрагивает вызов, — для потолка
	// пакета. Ограничение придумано не ради экономии: чем меньше писем
	// в одном вызове, тем меньше вреда от неверно понятой просьбы.
	Batch func(a Args) int

	// Confirm — аргумент, без которого вызов не выполняется (обычно
	// "confirm"). Проверка здесь, а не в Do: забыть её в одном из
	// удаляющих инструментов — вопрос времени.
	Confirm string

	// Do выполняет вызов. Возвращаемое значение: string уходит текстом,
	// всё остальное сериализуется в JSON.
	Do func(ctx context.Context, a Args) (any, error)
}

// Add регистрирует инструмент. Здесь и только здесь: разбор
// аргументов, проверка права, подтверждение, размер пачки, вызов,
// подсказка к отказу, сериализация и обрезка.
func (r *Registry) Add(s Spec) {
	r.register(mcp.Tool{
		Name:        s.Name,
		Description: s.Desc,
		InputSchema: s.Schema,
		Handler: func(ctx context.Context, raw json.RawMessage) (string, error) {
			args := Args{}
			if len(raw) > 0 && string(raw) != "null" {
				if err := json.Unmarshal(raw, &args); err != nil {
					return "", fmt.Errorf("не разобрать аргументы: %w", err)
				}
			}

			safety := r.safetyFor(ctx)
			if err := safety.Check(s.Name, s.Access); err != nil {
				return "", err
			}
			if s.Confirm != "" && !args.Bool(s.Confirm) {
				return "", fmt.Errorf("%s необратим или затрагивает много писем: нужен аргумент %s: true. "+
					"Перед этим покажите человеку, что именно будет сделано, и получите его согласие", s.Name, s.Confirm)
			}
			if s.Batch != nil {
				if err := safety.CheckBatchSize(s.Batch(args)); err != nil {
					return "", err
				}
			}

			out, err := s.Do(ctx, args)
			if err != nil {
				return "", decorate(err)
			}
			if text, ok := out.(string); ok {
				return safety.TrimResponse(text), nil
			}
			body, err := json.Marshal(out)
			if err != nil {
				return "", fmt.Errorf("сериализация ответа: %w", err)
			}
			return safety.TrimResponse(formatJSON(body)), nil
		},
	})
}

// AddCustom регистрирует инструмент с собственным обработчиком.
func (r *Registry) AddCustom(t mcp.Tool) { r.register(t) }

// register — общая обёртка всех инструментов: сообщение наблюдателю
// о вызове.
func (r *Registry) register(t mcp.Tool) {
	inner := t.Handler
	name := t.Name
	t.Handler = func(ctx context.Context, raw json.RawMessage) (string, error) {
		out, err := inner(ctx, raw)
		if h, ok := ctx.Value(hookKey{}).(CallHook); ok && h != nil {
			h(name, err != nil)
		}
		return out, err
	}
	r.server.Register(t)
}

// ErrNoAccounts — у подключения нет ни одного ящика.
var ErrNoAccounts = errors.New("к этому подключению не привязан ни один почтовый ящик. " +
	"Локально — задайте MAIL_IMAP_<ID>_HOST/USER/PASS; в сервисе — подключите ящик в кабинете")

// client находит ящик по account_id.
//
// Пустой account_id допустим, только если ящик один: угадывать, из
// какого из трёх ящиков модель собралась отправить письмо, нельзя.
func (r *Registry) client(ctx context.Context, a Args) (*mail.Client, error) {
	return r.clientByID(ctx, a.Str("account_id"))
}

func (r *Registry) clientByID(ctx context.Context, id string) (*mail.Client, error) {
	list, ok := r.accountsFor(ctx)
	if !ok || len(list) == 0 {
		return nil, ErrNoAccounts
	}
	id = strings.TrimSpace(id)
	if id == "" {
		if len(list) == 1 {
			return mail.New(list[0], r.cfg.MailOptions...), nil
		}
		for _, acc := range list {
			if acc.ID == "default" {
				return mail.New(acc, r.cfg.MailOptions...), nil
			}
		}
		return nil, &mail.Error{Kind: mail.KindInput, Msg: "ящиков несколько — укажите account_id: " + accountIDs(list)}
	}
	for _, acc := range list {
		if strings.EqualFold(acc.ID, id) {
			return mail.New(acc, r.cfg.MailOptions...), nil
		}
	}
	return nil, &mail.Error{Kind: mail.KindInput, Msg: fmt.Sprintf("ящика %q нет; доступны: %s", id, accountIDs(list))}
}

func accountIDs(list []mail.Account) string {
	ids := make([]string, len(list))
	for i, a := range list {
		ids[i] = a.ID
	}
	return strings.Join(ids, ", ")
}

// prettyLimit — до какого размера ответ печатается с отступами.
//
// Отступы стоят дороже, чем кажется: на длинном списке писем они
// раздувают ответ почти вдвое, и ровно на этом он перестаёт доезжать
// до модели. Пока ответ короткий, читаемость важнее.
const prettyLimit = 8_000

// formatJSON печатает JSON: короткий — с отступами, длинный — плотно.
func formatJSON(raw []byte) string {
	if len(raw) <= prettyLimit {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, raw, "", "  "); err == nil {
			return pretty.String()
		}
	}
	return string(raw)
}

// decorate добавляет к ошибке совет человеку. Совет зависит от класса:
// на неверный пароль — идти за паролем приложения, на обрыв — проверять
// адрес и порт. Совет не из того класса стоит вечера.
func decorate(err error) error {
	if hint := mail.Hint(err); hint != "" {
		return fmt.Errorf("%w\n\n%s", err, hint)
	}
	return err
}
