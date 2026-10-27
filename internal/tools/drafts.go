package tools

import (
	"context"

	"github.com/MainAlexStark/email-mcp/mail"
)

// RegisterDrafts — черновики в папке Drafts ящика.
//
// Черновики — середина между «только читать» и «отправлять»: модель
// готовит письмо, человек открывает его в своей почте, правит и
// отправляет сам. Поэтому у них отдельное право, а отправка черновика
// требует права на отправку.
func (r *Registry) RegisterDrafts() {
	draftID := str("draft_id из draft_create или draft_list.")

	r.Add(Spec{
		Name: "draft_create",
		Desc: "Сохранить письмо черновиком в папке «Черновики» ящика. Ничего не отправляется: человек увидит " +
			"черновик в своей почте и отправит сам (или попросит draft_send).",
		Access: AccessDrafts,
		Schema: schema(composeFields(r), "subject"),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			o, err := r.outgoing(a)
			if err != nil {
				return nil, err
			}
			res, err := c.CreateDraft(ctx, o)
			if err != nil {
				return nil, err
			}
			return draftOut(c, res), nil
		},
	})

	r.Add(Spec{
		Name: "draft_update",
		Desc: "Заменить черновик целиком: получатели, тема, текст, вложения (не перечисленные вложения " +
			"пропадут). Возвращает новый draft_id — старый перестаёт работать.",
		Access: AccessDrafts,
		Schema: schema(merge(composeFields(r), obj{"draft_id": draftID}), "draft_id", "subject"),
		Do: func(ctx context.Context, a Args) (any, error) {
			id, err := a.messageID("draft_id")
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, id.Account)
			if err != nil {
				return nil, err
			}
			o, err := r.outgoing(a)
			if err != nil {
				return nil, err
			}
			res, err := c.UpdateDraft(ctx, id, o)
			if err != nil {
				return nil, err
			}
			return draftOut(c, res), nil
		},
	})

	r.Add(Spec{
		Name:    "draft_delete",
		Desc:    "Удалить черновик безвозвратно. Работает только с письмами из папки черновиков.",
		Access:  AccessDrafts,
		Confirm: "confirm",
		Schema: schema(obj{
			"account_id": accountField(),
			"draft_id":   draftID,
			"confirm":    boolean("Обязательно true."),
		}, "draft_id", "confirm"),
		Do: func(ctx context.Context, a Args) (any, error) {
			id, err := a.messageID("draft_id")
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, id.Account)
			if err != nil {
				return nil, err
			}
			if err := c.DeleteDraft(ctx, id); err != nil {
				return nil, err
			}
			return obj{"status": "ok", "draft_id": id.String(), "deleted": true}, nil
		},
	})

	r.Add(Spec{
		Name: "draft_list",
		Desc: "Черновики ящика, новые первыми, с draft_id.",
		Schema: schema(obj{
			"account_id": accountField(),
			"limit":      num("Сколько вернуть, 1–50, по умолчанию 20."),
		}),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			limit, err := a.Int("limit", 20, 1, 50)
			if err != nil {
				return nil, err
			}
			list, err := c.ListDrafts(ctx, limit)
			if err != nil {
				return nil, err
			}
			return obj{"account_id": c.Account().ID, "returned": len(list), "drafts": list}, nil
		},
	})

	r.Add(Spec{
		Name: "draft_send",
		Desc: "Отправить черновик и убрать его из черновиков. Скрытая копия (Bcc) вырезается из заголовков, " +
			"дата обновляется." + previewRule + " Предпросмотр — через imap_get_message по draft_id.",
		Access: AccessSend,
		Schema: schema(obj{
			"account_id":              accountField(),
			"draft_id":                draftID,
			"confirm_many_recipients": boolean("true, если человек подтвердил отправку на число адресов больше порога."),
		}, "draft_id"),
		Do: func(ctx context.Context, a Args) (any, error) {
			id, err := a.messageID("draft_id")
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, id.Account)
			if err != nil {
				return nil, err
			}
			msg, err := c.GetMessage(ctx, id, mail.GetOptions{IncludeAllHeaders: true, BodyMaxChars: 100})
			if err != nil {
				return nil, err
			}
			n := countHeaderAddrs(msg)
			if err := r.safetyFor(ctx).CheckRecipients(n, a.Bool("confirm_many_recipients")); err != nil {
				return nil, err
			}
			res, err := c.SendDraft(ctx, id)
			if err != nil {
				return nil, err
			}
			status := "ok"
			if len(res.Issues) > 0 {
				status = "partial"
			}
			return obj{"status": status, "account_id": c.Account().ID, "result": res}, nil
		},
	})
}

func countHeaderAddrs(m *mail.Message) int {
	n := 0
	for _, h := range m.Headers {
		switch h.Name {
		case "To", "Cc", "Bcc":
			if list, err := mail.ParseAddressList(h.Value); err == nil {
				n += len(list)
			}
		}
	}
	return n
}

func draftOut(c *mail.Client, res mail.DraftResult) obj {
	status := "ok"
	if len(res.Issues) > 0 {
		status = "partial"
	}
	return obj{"status": status, "account_id": c.Account().ID, "backend": "imap", "result": res}
}
