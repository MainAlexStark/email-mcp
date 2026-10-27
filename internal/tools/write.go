package tools

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/emersion/go-imap/v2"

	"github.com/MainAlexStark/email-mcp/mail"
)

func flagsField(desc string) obj {
	return arr(str(""), desc+` Системные: \Seen (прочитано), \Flagged (важное), \Answered, \Draft; свои — одно слово.`)
}

// idsArg разбирает message_ids и проверяет, что все из одного ящика.
func idsArg(a Args) ([]mail.MessageID, error) {
	raw, err := a.Strings("message_ids")
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, inputf("message_ids пуст")
	}
	if len(raw) > 500 {
		return nil, inputf("не больше 500 писем за вызов")
	}
	out := make([]mail.MessageID, 0, len(raw))
	for _, s := range raw {
		id, err := mail.ParseMessageID(s)
		if err != nil {
			return nil, err
		}
		if len(out) > 0 && id.Account != out[0].Account {
			return nil, inputf("все message_ids должны быть из одного ящика: %s и %s", out[0].Account, id.Account)
		}
		out = append(out, id)
	}
	if acc := a.Str("account_id"); acc != "" && !strings.EqualFold(acc, out[0].Account) {
		return nil, inputf("message_ids из ящика %q, а account_id=%q", out[0].Account, acc)
	}
	return out, nil
}

func countIDs(a Args) int {
	ids, _ := a.Strings("message_ids")
	return len(ids)
}

func limitBatch(a Args) int {
	n, _ := a.Int("limit", 100, 1, 500)
	return n
}

func bulkStatus(done, failed int) string {
	switch {
	case failed == 0:
		return "ok"
	case done == 0:
		return "failed"
	}
	return "partial"
}

// RegisterWrite — изменение ящика: флаги, перенос, удаление, папки.
func (r *Registry) RegisterWrite() {
	r.Add(Spec{
		Name:   "imap_update_message_flags",
		Desc:   "Поставить или снять флаги письма: прочитано, важное, свои метки.",
		Access: AccessWrite,
		Schema: schema(obj{
			"account_id":   accountField(),
			"message_id":   messageIDField(),
			"add_flags":    flagsField("Какие флаги поставить."),
			"remove_flags": flagsField("Какие флаги снять."),
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
			add, err := a.Strings("add_flags")
			if err != nil {
				return nil, err
			}
			rem, err := a.Strings("remove_flags")
			if err != nil {
				return nil, err
			}
			flags, err := c.UpdateFlags(ctx, id, add, rem)
			if err != nil {
				return nil, err
			}
			return obj{"message_id": id.String(), "flags": flags}, nil
		},
	})

	r.Add(Spec{
		Name: "imap_copy_message",
		Desc: "Скопировать письмо в папку этого же или другого ящика (destination_account_id). " +
			"Исходное остаётся на месте.",
		Access: AccessWrite,
		Schema: schema(obj{
			"account_id":             accountField(),
			"message_id":             messageIDField(),
			"destination_mailbox":    mailboxField(),
			"destination_account_id": str("Ящик назначения, если не тот же."),
		}, "message_id", "destination_mailbox"),
		Do: func(ctx context.Context, a Args) (any, error) {
			id, err := a.messageID("message_id")
			if err != nil {
				return nil, err
			}
			src, err := r.clientByID(ctx, id.Account)
			if err != nil {
				return nil, err
			}
			dest := a.Str("destination_mailbox")
			destAcc := a.Str("destination_account_id")
			if destAcc == "" || strings.EqualFold(destAcc, id.Account) {
				res, err := src.Copy(ctx, id, dest)
				if err != nil {
					return nil, err
				}
				return res, nil
			}
			// Между ящиками COPY не работает: это разные серверы.
			// Письмо читается целиком и кладётся APPEND с теми же флагами.
			dst, err := r.clientByID(ctx, destAcc)
			if err != nil {
				return nil, err
			}
			raw, flags, err := src.FetchRaw(ctx, id)
			if err != nil {
				return nil, err
			}
			var fl []imap.Flag
			for _, f := range flags {
				if f != `\Recent` && f != string(imap.FlagDeleted) {
					fl = append(fl, imap.Flag(f))
				}
			}
			res, err := dst.Append(ctx, dest, raw, fl)
			if err != nil {
				return nil, err
			}
			return obj{"message_id": id.String(), "destination_account_id": dst.Account().ID,
				"destination_mailbox": res.Mailbox, "new_message_id": res.MessageID}, nil
		},
	})

	r.Add(Spec{
		Name: "imap_move_message",
		Desc: "Перенести письмо в другую папку этого ящика. Возвращает new_message_id: старый id после " +
			"переноса не работает.",
		Access: AccessWrite,
		Schema: schema(obj{
			"account_id":          accountField(),
			"message_id":          messageIDField(),
			"destination_mailbox": mailboxField(),
		}, "message_id", "destination_mailbox"),
		Do: func(ctx context.Context, a Args) (any, error) {
			id, err := a.messageID("message_id")
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, id.Account)
			if err != nil {
				return nil, err
			}
			return c.Move(ctx, id, a.Str("destination_mailbox"))
		},
	})

	deleteDesc := " По умолчанию письма уходят в корзину, откуда их можно вернуть; permanent: true стирает " +
		"безвозвратно (из корзины удаление всегда безвозвратное). Перед вызовом покажите человеку, что " +
		"будет удалено, и получите согласие."

	r.Add(Spec{
		Name:    "imap_delete_message",
		Desc:    "Удалить письмо." + deleteDesc,
		Access:  AccessWrite,
		Confirm: "confirm",
		Schema: schema(obj{
			"account_id": accountField(),
			"message_id": messageIDField(),
			"permanent":  boolean("Стереть безвозвратно, минуя корзину."),
			"confirm":    boolean("Обязательно true: подтверждение, что человек согласен."),
		}, "message_id", "confirm"),
		Do: func(ctx context.Context, a Args) (any, error) {
			id, err := a.messageID("message_id")
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, id.Account)
			if err != nil {
				return nil, err
			}
			res, err := c.DeleteMany(ctx, []mail.MessageID{id}, mail.DeleteMode{Permanent: a.Bool("permanent")})
			if err != nil {
				return nil, err
			}
			if len(res.Failed) > 0 {
				return nil, &mail.Error{Kind: mail.KindServer, Msg: res.Failed[0].Error}
			}
			return res, nil
		},
	})

	r.Add(Spec{
		Name:   "imap_create_mailbox",
		Desc:   `Создать папку. Вложенность — через разделитель ящика (delimiter из imap_list_mailboxes), например "Проекты/2026".`,
		Access: AccessWrite,
		Schema: schema(obj{"account_id": accountField(), "mailbox_name": str("Имя новой папки.")}, "mailbox_name"),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			if err := c.CreateMailbox(ctx, a.Str("mailbox_name")); err != nil {
				return nil, err
			}
			return obj{"created": a.Str("mailbox_name")}, nil
		},
	})

	r.Add(Spec{
		Name: "imap_delete_mailbox",
		Desc: "Удалить папку ВМЕСТЕ С ПИСЬМАМИ — безвозвратно. Системные папки (Входящие, Отправленные, " +
			"Корзина…) не удаляются. Сначала покажите человеку, сколько в папке писем (imap_mailbox_status).",
		Access:  AccessWrite,
		Confirm: "confirm",
		Schema: schema(obj{
			"account_id":   accountField(),
			"mailbox_name": str("Точное имя папки."),
			"confirm":      boolean("Обязательно true."),
		}, "mailbox_name", "confirm"),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			if err := c.DeleteMailbox(ctx, a.Str("mailbox_name")); err != nil {
				return nil, err
			}
			return obj{"deleted": a.Str("mailbox_name")}, nil
		},
	})

	r.Add(Spec{
		Name:   "imap_rename_mailbox",
		Desc:   "Переименовать папку. message_id писем в ней после этого устаревают.",
		Access: AccessWrite,
		Schema: schema(obj{
			"account_id": accountField(),
			"from_name":  str("Текущее имя."),
			"to_name":    str("Новое имя."),
		}, "from_name", "to_name"),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			if err := c.RenameMailbox(ctx, a.Str("from_name"), a.Str("to_name")); err != nil {
				return nil, err
			}
			return obj{"renamed": a.Str("from_name"), "to": a.Str("to_name")}, nil
		},
	})

	idsField := arr(messageIDField(), "message_id писем одного ящика, до 500 (и не больше лимита пакета сервера).")

	r.Add(Spec{
		Name:   "imap_bulk_move",
		Desc:   "Перенести несколько писем в папку одним вызовом. Ошибка одной папки не отменяет остальные.",
		Access: AccessWrite,
		Batch:  countIDs,
		Schema: schema(obj{
			"account_id":          accountField(),
			"message_ids":         idsField,
			"destination_mailbox": mailboxField(),
		}, "message_ids", "destination_mailbox"),
		Do: func(ctx context.Context, a Args) (any, error) {
			ids, err := idsArg(a)
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, ids[0].Account)
			if err != nil {
				return nil, err
			}
			res, err := c.MoveMany(ctx, ids, a.Str("destination_mailbox"))
			if err != nil {
				return nil, err
			}
			return obj{"status": bulkStatus(len(res.Done), len(res.Failed)), "result": res}, nil
		},
	})

	r.Add(Spec{
		Name:    "imap_bulk_delete",
		Desc:    "Удалить несколько писем одним вызовом." + deleteDesc,
		Access:  AccessWrite,
		Confirm: "confirm",
		Batch:   countIDs,
		Schema: schema(obj{
			"account_id":  accountField(),
			"message_ids": idsField,
			"permanent":   boolean("Стереть безвозвратно, минуя корзину."),
			"confirm":     boolean("Обязательно true."),
		}, "message_ids", "confirm"),
		Do: func(ctx context.Context, a Args) (any, error) {
			ids, err := idsArg(a)
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, ids[0].Account)
			if err != nil {
				return nil, err
			}
			res, err := c.DeleteMany(ctx, ids, mail.DeleteMode{Permanent: a.Bool("permanent")})
			if err != nil {
				return nil, err
			}
			return obj{"status": bulkStatus(len(res.Done), len(res.Failed)), "result": res}, nil
		},
	})

	r.Add(Spec{
		Name:   "imap_bulk_update_flags",
		Desc:   "Поставить или снять флаги у нескольких писем — например, отметить прочитанными.",
		Access: AccessWrite,
		Batch:  countIDs,
		Schema: schema(obj{
			"account_id":   accountField(),
			"message_ids":  idsField,
			"add_flags":    flagsField("Какие флаги поставить."),
			"remove_flags": flagsField("Какие флаги снять."),
		}, "message_ids"),
		Do: func(ctx context.Context, a Args) (any, error) {
			ids, err := idsArg(a)
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, ids[0].Account)
			if err != nil {
				return nil, err
			}
			add, err := a.Strings("add_flags")
			if err != nil {
				return nil, err
			}
			rem, err := a.Strings("remove_flags")
			if err != nil {
				return nil, err
			}
			res, err := c.FlagsMany(ctx, ids, add, rem)
			if err != nil {
				return nil, err
			}
			return obj{"status": bulkStatus(len(res.Done), len(res.Failed)), "result": res}, nil
		},
	})

	r.Add(Spec{
		Name:   "imap_append_message",
		Desc:   "Положить готовое письмо (RFC 822) в папку — например, импорт из файла. Ничего не отправляет.",
		Access: AccessWrite,
		Schema: schema(obj{
			"account_id":         accountField(),
			"mailbox":            mailboxField(),
			"raw_message":        str("Письмо целиком: заголовки, пустая строка, тело."),
			"raw_message_base64": str("То же в base64 — для писем с бинарными частями."),
			"flags":              flagsField("Флаги нового письма."),
		}, "mailbox"),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			raw := normalizeCRLF([]byte(a.Raw("raw_message")))
			if b := a.Str("raw_message_base64"); b != "" {
				if raw, err = base64.StdEncoding.DecodeString(b); err != nil {
					return nil, inputf("raw_message_base64 не разобран: %v", err)
				}
			}
			if len(raw) == 0 {
				return nil, inputf("нужен raw_message или raw_message_base64")
			}
			if len(raw) > mail.MaxAttachmentsBytes {
				return nil, inputf("письмо больше %d МБ", mail.MaxAttachmentsBytes>>20)
			}
			if _, err := mail.Parse(raw); err != nil {
				return nil, inputf("это не похоже на письмо RFC 822: %v", err)
			}
			fl, err := a.Strings("flags")
			if err != nil {
				return nil, err
			}
			flags, err := mail.ValidFlags(fl)
			if err != nil {
				return nil, err
			}
			return c.Append(ctx, a.Str("mailbox"), raw, flags)
		},
	})

	searchAndProps := func(extra obj) obj {
		return merge(obj{
			"account_id": accountField(),
			"mailbox":    mailboxField(),
			"limit":      num("Сколько найденных писем обработать, 1–500, по умолчанию 100 (не больше лимита пакета сервера)."),
		}, searchFields(), extra)
	}

	r.Add(Spec{
		Name: "imap_search_and_move",
		Desc: "Найти письма и перенести найденное в папку одним вызовом (новые первыми, до limit). " +
			"Нужно хотя бы одно условие поиска.",
		Access: AccessWrite,
		Batch:  limitBatch,
		Schema: schema(searchAndProps(obj{"destination_mailbox": mailboxField()}), "mailbox", "destination_mailbox"),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			crit, err := a.criteria()
			if err != nil {
				return nil, err
			}
			ids, total, err := c.SearchIDs(ctx, a.Str("mailbox"), crit, limitBatch(a))
			if err != nil {
				return nil, err
			}
			if len(ids) == 0 {
				return obj{"status": "ok", "matched": 0}, nil
			}
			res, err := c.MoveMany(ctx, ids, a.Str("destination_mailbox"))
			if err != nil {
				return nil, err
			}
			return obj{"status": bulkStatus(len(res.Done), len(res.Failed)), "matched": total,
				"processed": len(ids), "result": res}, nil
		},
	})

	r.Add(Spec{
		Name: "imap_search_and_delete",
		Desc: "Найти письма и удалить найденное одним вызовом (новые первыми, до limit)." + deleteDesc +
			" Сначала покажите человеку результат того же поиска через imap_search_messages.",
		Access:  AccessWrite,
		Confirm: "confirm",
		Batch:   limitBatch,
		Schema: schema(searchAndProps(obj{
			"permanent": boolean("Стереть безвозвратно, минуя корзину."),
			"confirm":   boolean("Обязательно true."),
		}), "mailbox", "confirm"),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			crit, err := a.criteria()
			if err != nil {
				return nil, err
			}
			ids, total, err := c.SearchIDs(ctx, a.Str("mailbox"), crit, limitBatch(a))
			if err != nil {
				return nil, err
			}
			if len(ids) == 0 {
				return obj{"status": "ok", "matched": 0}, nil
			}
			res, err := c.DeleteMany(ctx, ids, mail.DeleteMode{Permanent: a.Bool("permanent")})
			if err != nil {
				return nil, err
			}
			return obj{"status": bulkStatus(len(res.Done), len(res.Failed)), "matched": total,
				"processed": len(ids), "result": res}, nil
		},
	})
}

// normalizeCRLF приводит переводы строк к CRLF: модель присылает \n,
// а IMAP APPEND требует CRLF, и часть серверов иначе отвергает письмо.
func normalizeCRLF(b []byte) []byte {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	return []byte(strings.ReplaceAll(s, "\n", "\r\n"))
}
