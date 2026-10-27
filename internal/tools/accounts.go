package tools

import (
	"context"
	"strings"

	"github.com/MainAlexStark/email-mcp/mail"
)

// accountView — ящик для модели, без пароля и логина.
type accountView struct {
	AccountID   string       `json:"account_id"`
	Email       string       `json:"email,omitempty"`
	DisplayName string       `json:"display_name,omitempty"`
	IMAP        mail.Server  `json:"imap"`
	SMTP        *mail.Server `json:"smtp,omitempty"`
	CanSend     bool         `json:"can_send"`
	DraftsWith  string       `json:"drafts_with"`
}

func viewOf(acc mail.Account) accountView {
	v := accountView{AccountID: acc.ID, Email: acc.Sender(), DisplayName: acc.DisplayName,
		IMAP: acc.IMAP, DraftsWith: "imap"}
	if acc.SMTP.Configured() {
		s := acc.SMTP
		v.SMTP = &s
		v.CanSend = true
	}
	return v
}

// RegisterAccounts — ящики, проверка входа и справка по провайдерам.
func (r *Registry) RegisterAccounts() {
	r.Add(Spec{
		Name: "list_all_accounts",
		Desc: "Ящики, доступные этому подключению, и права подключения (чтение, черновики, изменение, отправка). " +
			"Вызовите первым: account_id отсюда передаётся во все остальные инструменты.",
		Schema: schema(obj{}),
		Do: func(ctx context.Context, _ Args) (any, error) {
			list, _ := r.accountsFor(ctx)
			views := make([]accountView, 0, len(list))
			for _, acc := range list {
				views = append(views, viewOf(acc))
			}
			s := r.safetyFor(ctx)
			out := obj{
				"accounts":    views,
				"permissions": obj{"read": true, "drafts": s.Drafts, "write": s.Write, "send": s.Send},
			}
			if len(views) == 0 {
				out["hint"] = ErrNoAccounts.Error()
			}
			return out, nil
		},
	})

	r.Add(Spec{
		Name:   "imap_list_accounts",
		Desc:   "Ящики с адресами IMAP-серверов (совместимость с mail-mcp; полный вид — list_all_accounts).",
		Schema: schema(obj{}),
		Do: func(ctx context.Context, _ Args) (any, error) {
			list, _ := r.accountsFor(ctx)
			out := make([]obj, 0, len(list))
			for _, acc := range list {
				out = append(out, obj{"account_id": acc.ID, "host": acc.IMAP.Host, "port": acc.IMAP.Port,
					"secure": acc.IMAP.Security != mail.SecurityNone})
			}
			return obj{"accounts": out}, nil
		},
	})

	r.Add(Spec{
		Name:   "imap_verify_account",
		Desc:   "Проверить вход в ящик по IMAP и возможности сервера. Первое, что стоит вызвать, если чтение не работает.",
		Schema: schema(obj{"account_id": accountField()}),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			res, err := c.VerifyIMAP(ctx)
			if err != nil {
				return nil, err
			}
			return obj{"account_id": c.Account().ID, "result": res}, nil
		},
	})

	r.Add(Spec{
		Name:   "smtp_verify_account",
		Desc:   "Проверить вход на SMTP-сервер ящика, ничего не отправляя.",
		Schema: schema(obj{"account_id": accountField()}),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			res, err := c.VerifySMTP(ctx)
			if err != nil {
				return nil, err
			}
			return obj{"account_id": c.Account().ID, "result": res}, nil
		},
	})

	r.Add(Spec{
		Name: "get_setup_guide",
		Desc: "Как подключить ящик известного провайдера: серверы, порты и где взять пароль приложения " +
			"(Gmail, Яндекс, Mail.ru, iCloud, Outlook и др.). Укажите email или provider.",
		Schema: schema(obj{
			"email":    str("Адрес ящика — провайдер определится по домену."),
			"provider": str("Название провайдера, если адреса нет: gmail, yandex, mail.ru, icloud…"),
		}),
		Do: func(_ context.Context, a Args) (any, error) {
			if e := a.Str("email"); e != "" {
				if p, ok := mail.ProviderFor(e); ok {
					return p, nil
				}
				return obj{"found": false, "hint": "Домен не из списка известных провайдеров — " +
					"адреса IMAP/SMTP узнайте у администратора почты или в справке хостинга. " +
					"Обычно это imap.<домен>:993 (tls) и smtp.<домен>:465 (tls) или :587 (starttls).",
					"password": mail.CustomDomainGuide}, nil
			}
			if q := strings.ToLower(a.Str("provider")); q != "" {
				for _, p := range mail.Providers {
					if strings.Contains(strings.ToLower(p.Name), q) || strings.Contains(strings.Join(p.Domains, " "), q) {
						return p, nil
					}
				}
			}
			return obj{"providers": mail.Providers}, nil
		},
	})
}
