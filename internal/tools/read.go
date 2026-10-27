package tools

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/MainAlexStark/email-mcp/internal/files"
	"github.com/MainAlexStark/email-mcp/mail"
)

// Поля, общие для многих инструментов. Описание поля — то, что модель
// читает перед вызовом; поле без описания она заполняет догадкой.

func accountField() obj {
	return str("Ящик — account_id из list_all_accounts. Можно не указывать, если ящик один.")
}

func mailboxField() obj {
	return str(`Папка: имя из imap_list_mailboxes. Работают и роли: "INBOX", "Sent", "Drafts", "Trash", "Junk" — ` +
		`они сами находят «Отправленные», «[Gmail]/Sent Mail» и т. п.`)
}

func messageIDField() obj {
	return str("message_id из imap_search_messages: imap:{account}:{mailbox}:{uidvalidity}:{uid}.")
}

func searchFields() obj {
	return obj{
		"query":             str("Текст в любом месте письма (IMAP TEXT). Медленнее остальных условий на больших папках."),
		"from":              str("Подстрока адреса или имени отправителя."),
		"to":                str("Подстрока адреса или имени получателя."),
		"subject":           str("Подстрока темы."),
		"thread_message_id": str("Message-ID письма (<id@host>): найдёт его и все ответы на него — вся переписка разом."),
		"unread_only":       boolean("Только непрочитанные."),
		"last_days":         num("За последние N дней (1–3650). Не сочетается с start_date/end_date."),
		"start_date":        str("С даты, ГГГГ-ММ-ДД, включительно."),
		"end_date":          str("По дату, ГГГГ-ММ-ДД, включительно."),
	}
}

func merge(parts ...obj) obj {
	out := obj{}
	for _, p := range parts {
		for k, v := range p {
			out[k] = v
		}
	}
	return out
}

// RegisterRead — чтение писем и папок.
func (r *Registry) RegisterRead() {
	r.Add(Spec{
		Name: "imap_list_mailboxes",
		Desc: "Список папок ящика с ролями (sent, drafts, trash, junk, archive). " +
			"Вызовите перед поиском, если не знаете, как у этого провайдера называются папки.",
		Schema: schema(obj{"account_id": accountField()}),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			list, err := c.ListMailboxes(ctx)
			if err != nil {
				return nil, err
			}
			total := len(list)
			truncated := total > r.cfg.MaxMailboxes
			if truncated {
				list = list[:r.cfg.MaxMailboxes]
			}
			return obj{"account_id": c.Account().ID, "mailboxes": list, "total": total, "truncated": truncated}, nil
		},
	})

	r.Add(Spec{
		Name:   "imap_mailbox_status",
		Desc:   "Сколько писем и непрочитанных в папке — без открытия и без загрузки писем. Дешевле поиска.",
		Schema: schema(obj{"account_id": accountField(), "mailbox": mailboxField()}, "mailbox"),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			return c.Status(ctx, a.Str("mailbox"))
		},
	})

	r.Add(Spec{
		Name: "imap_search_messages",
		Desc: "Поиск писем в одной папке, новые первыми, постранично. Возвращает message_id для остальных " +
			"инструментов. Следующая страница — тот же вызов с cursor из next_cursor (и без условий).",
		Schema: schema(merge(obj{
			"account_id":        accountField(),
			"mailbox":           mailboxField(),
			"cursor":            str("next_cursor из прошлого ответа. С ним условия поиска не передаются."),
			"limit":             with(num("Писем на страницу, 1–50, по умолчанию 10."), obj{"minimum": 1, "maximum": 50}),
			"include_snippet":   boolean("Добавить фрагмент текста каждого письма (дороже)."),
			"snippet_max_chars": num("Длина фрагмента, 50–500, по умолчанию 200."),
		}, searchFields())),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			cursor := a.Str("cursor")
			var crit mail.Criteria
			if cursor == "" {
				if a.Str("mailbox") == "" {
					return nil, inputf("нужен mailbox (например INBOX) или cursor")
				}
				if crit, err = a.criteria(); err != nil {
					return nil, err
				}
			} else if c2, err := a.criteria(); err == nil && !c2.Empty() {
				return nil, inputf("cursor нельзя сочетать с условиями поиска: условия уже внутри курсора")
			}
			limit, err := a.Int("limit", 10, 1, 50)
			if err != nil {
				return nil, err
			}
			snip, err := a.Int("snippet_max_chars", 200, 50, 500)
			if err != nil {
				return nil, err
			}
			opt := mail.SearchOptions{Limit: limit, IncludeSnippet: a.Bool("include_snippet"), SnippetMaxChars: snip}
			res, err := c.Search(ctx, a.Str("mailbox"), crit, opt, cursor)
			if err != nil {
				return nil, err
			}
			out := obj{"account_id": c.Account().ID, "result": res}
			if res.HasMore {
				out["next_action"] = obj{"instruction": "Есть ещё письма — повторите вызов с cursor",
					"tool": "imap_search_messages", "arguments": obj{"account_id": c.Account().ID, "cursor": res.NextCursor}}
			}
			return out, nil
		},
	})

	r.Add(Spec{
		Name: "imap_search_all_mailboxes",
		Desc: "Один поиск сразу во всех папках ящика, новые первыми, у каждого письма указана папка. " +
			"Нужен, когда переписка разложена по «Входящим», «Отправленным» и проектным папкам — например, " +
			"вся цепочка по thread_message_id. Нужно хотя бы одно условие.",
		Schema: schema(merge(obj{
			"account_id":        accountField(),
			"include_mailboxes": arr(str(""), "Искать только в этих папках (и их подпапках)."),
			"exclude_mailboxes": arr(str(""), "Не искать в этих папках (и подпапках); важнее include."),
			"limit":             num("Сколько писем вернуть, 1–200, по умолчанию 50."),
			"include_snippet":   boolean("Добавить фрагмент текста."),
			"snippet_max_chars": num("Длина фрагмента, 50–500."),
		}, searchFields())),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			crit, err := a.criteria()
			if err != nil {
				return nil, err
			}
			limit, err := a.Int("limit", 50, 1, 200)
			if err != nil {
				return nil, err
			}
			snip, err := a.Int("snippet_max_chars", 200, 50, 500)
			if err != nil {
				return nil, err
			}
			inc, err := a.Strings("include_mailboxes")
			if err != nil {
				return nil, err
			}
			exc, err := a.Strings("exclude_mailboxes")
			if err != nil {
				return nil, err
			}
			res, err := c.SearchAll(ctx, crit, mail.SearchAllOptions{
				SearchOptions: mail.SearchOptions{Limit: limit, IncludeSnippet: a.Bool("include_snippet"), SnippetMaxChars: snip},
				Include:       inc, Exclude: exc, Concurrency: r.cfg.SearchConcurrency,
			})
			if err != nil {
				return nil, err
			}
			status := "ok"
			if len(res.Failed) > 0 {
				status = "partial"
			}
			return obj{"account_id": c.Account().ID, "status": status, "result": res}, nil
		},
	})

	r.Add(Spec{
		Name: "imap_get_message",
		Desc: "Прочитать письмо: заголовки, текст, список вложений с part_id. HTML по запросу и только " +
			"очищенный. Текст из PDF и текстовых вложений — по extract_attachment_text.",
		Schema: schema(obj{
			"account_id":                accountField(),
			"message_id":                messageIDField(),
			"body_max_chars":            num("Сколько символов текста вернуть, 100–20000, по умолчанию 2000."),
			"include_headers":           boolean("Основные заголовки (по умолчанию да)."),
			"include_all_headers":       boolean("Все заголовки, включая Received и DKIM (для разбора доставки)."),
			"include_html":              boolean("Очищенный HTML письма."),
			"extract_attachment_text":   boolean("Достать текст из PDF и текстовых вложений до 5 МБ."),
			"attachment_text_max_chars": num("Сколько символов текста на вложение, 100–50000, по умолчанию 10000."),
		}, "message_id"),
		Do: func(ctx context.Context, a Args) (any, error) {
			id, err := a.messageID("message_id")
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, id.Account)
			if err != nil {
				return nil, err
			}
			bodyMax, err := a.Int("body_max_chars", 2000, 100, 20000)
			if err != nil {
				return nil, err
			}
			attMax, err := a.Int("attachment_text_max_chars", 10000, 100, 50000)
			if err != nil {
				return nil, err
			}
			headers := true
			if a.Has("include_headers") {
				headers = a.Bool("include_headers")
			}
			msg, err := c.GetMessage(ctx, id, mail.GetOptions{
				BodyMaxChars: bodyMax, IncludeHeaders: headers, IncludeAllHeaders: a.Bool("include_all_headers"),
				IncludeHTML: a.Bool("include_html"), ExtractAttachmentText: a.Bool("extract_attachment_text"),
				AttachmentTextMaxChars: attMax,
			})
			if err != nil {
				return nil, err
			}
			return obj{"account_id": c.Account().ID, "message": msg}, nil
		},
	})

	r.Add(Spec{
		Name: "imap_get_message_raw",
		Desc: "Исходник письма (RFC 822) в base64 — для разбора доставки и подписи. Для чтения письма есть imap_get_message.",
		Schema: schema(obj{
			"account_id": accountField(),
			"message_id": messageIDField(),
			"max_bytes":  num("Сколько байт вернуть, 1024–1000000, по умолчанию 200000."),
		}, "message_id"),
		Do: func(ctx context.Context, a Args) (any, error) {
			id, err := a.messageID("message_id")
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, id.Account)
			if err != nil {
				return nil, err
			}
			max, err := a.Int("max_bytes", 200_000, 1024, 1_000_000)
			if err != nil {
				return nil, err
			}
			raw, _, err := c.FetchRaw(ctx, id)
			if err != nil {
				return nil, err
			}
			size := len(raw)
			truncated := size > max
			if truncated {
				raw = raw[:max]
			}
			return obj{"message_id": id.String(), "size_bytes": size, "truncated": truncated,
				"raw_source_base64": base64.StdEncoding.EncodeToString(raw), "raw_source_encoding": "base64"}, nil
		},
	})

	r.Add(Spec{
		Name: "imap_get_attachment",
		Desc: "Скачать одно вложение письма (по part_id или имени файла из imap_get_message). Файл сохраняется " +
			"и возвращается ссылка или путь — содержимое в ответ не попадает, если не попросить include_base64 " +
			"для небольшого файла.",
		Schema: schema(obj{
			"account_id":       accountField(),
			"message_id":       messageIDField(),
			"part_id":          str("part_id из imap_get_message, например 2 или 1.2. Важнее filename."),
			"filename":         str("Имя файла вложения (без учёта регистра), если part_id не известен."),
			"include_base64":   boolean("Вернуть ещё и содержимое в base64 — только для файлов до max_inline_bytes."),
			"max_inline_bytes": num("Потолок для include_base64, по умолчанию 262144 (256 КБ)."),
		}, "message_id"),
		Do: func(ctx context.Context, a Args) (any, error) {
			id, err := a.messageID("message_id")
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, id.Account)
			if err != nil {
				return nil, err
			}
			part, err := c.GetAttachment(ctx, id, a.Str("part_id"), a.Str("filename"))
			if err != nil {
				return nil, err
			}
			name := mail.SafeFilename(part.Filename)
			if part.Filename == "" {
				name = "part-" + strings.ReplaceAll(part.PartID, ".", "-")
			}
			out := obj{"message_id": id.String(), "part_id": part.PartID, "filename": name,
				"content_type": part.ContentType, "size_bytes": len(part.Data)}
			if r.cfg.Files != nil {
				saved, err := r.cfg.Files.Save(name, part.ContentType, part.Data)
				if err != nil {
					out["save_error"] = err.Error()
				} else {
					out["location"] = saved.Location
					if !saved.Expires.IsZero() {
						out["expires"] = saved.Expires.Format("2006-01-02 15:04 MST")
					}
				}
			}
			if a.Bool("include_base64") {
				max, err := a.Int("max_inline_bytes", 256<<10, 1, 5<<20)
				if err != nil {
					return nil, err
				}
				if len(part.Data) > max {
					out["base64_skipped"] = fmt.Sprintf("вложение %d байт больше max_inline_bytes=%d", len(part.Data), max)
				} else {
					out["content_base64"] = base64.StdEncoding.EncodeToString(part.Data)
				}
			}
			if _, ok := out["location"]; !ok && out["content_base64"] == nil {
				out["hint"] = "сохранить файл некуда — повторите с include_base64: true"
			}
			return out, nil
		},
	})
}

// describeFiles объясняет, куда уходят сохранённые вложения.
func describeFiles(s files.Store) string {
	switch st := s.(type) {
	case *files.Dir:
		return "папка " + st.Root
	case *files.Memory:
		return fmt.Sprintf("ссылки на этот сервер, живут %s", st.TTL)
	case nil:
		return "сохранять некуда — imap_get_attachment отдаёт только base64"
	}
	return "своё хранилище"
}
