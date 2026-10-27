package mail

import "strings"

// Provider — настройки известного почтового сервиса.
type Provider struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	IMAP    Server   `json:"imap"`
	SMTP    Server   `json:"smtp"`
	// AppPassword — где взять пароль приложения; пусто — подходит обычный.
	AppPassword string `json:"app_password,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Providers — сервисы, которые узнаются по домену адреса. Человеку,
// который подключает ящик, не нужно знать слова «IMAP» и «993»:
// хватит адреса и пароля приложения.
var Providers = []Provider{
	{
		Name: "Gmail", Domains: []string{"gmail.com", "googlemail.com"},
		IMAP:        Server{"imap.gmail.com", 993, SecurityTLS},
		SMTP:        Server{"smtp.gmail.com", 465, SecurityTLS},
		AppPassword: "myaccount.google.com/apppasswords (нужна двухэтапная проверка)",
	},
	{
		Name: "Яндекс Почта", Domains: []string{"yandex.ru", "ya.ru", "yandex.com", "yandex.by", "yandex.kz", "narod.ru"},
		IMAP:        Server{"imap.yandex.ru", 993, SecurityTLS},
		SMTP:        Server{"smtp.yandex.ru", 465, SecurityTLS},
		AppPassword: "id.yandex.ru → Безопасность → Пароли приложений → Почта",
		Note:        "Включите IMAP: Почта → Все настройки → Почтовые программы.",
	},
	{
		Name: "Mail.ru", Domains: []string{"mail.ru", "bk.ru", "inbox.ru", "list.ru", "internet.ru"},
		IMAP:        Server{"imap.mail.ru", 993, SecurityTLS},
		SMTP:        Server{"smtp.mail.ru", 465, SecurityTLS},
		AppPassword: "Настройки → Безопасность → Пароли для внешних приложений",
	},
	{
		Name: "Рамблер", Domains: []string{"rambler.ru", "lenta.ru", "autorambler.ru", "myrambler.ru", "ro.ru"},
		IMAP: Server{"imap.rambler.ru", 993, SecurityTLS},
		SMTP: Server{"smtp.rambler.ru", 465, SecurityTLS},
		Note: "Включите доступ из почтовых программ: Настройки → Программы.",
	},
	{
		Name: "iCloud", Domains: []string{"icloud.com", "me.com", "mac.com"},
		IMAP:        Server{"imap.mail.me.com", 993, SecurityTLS},
		SMTP:        Server{"smtp.mail.me.com", 587, SecurityStartTLS},
		AppPassword: "appleid.apple.com → Вход и безопасность → Пароли приложений",
		Note:        "Логин — адрес без домена или полный адрес @icloud.com.",
	},
	{
		Name: "Outlook.com", Domains: []string{"outlook.com", "hotmail.com", "live.com", "msn.com"},
		IMAP: Server{"outlook.office365.com", 993, SecurityTLS},
		SMTP: Server{"smtp-mail.outlook.com", 587, SecurityStartTLS},
		Note: "Microsoft отключает вход по паролю для IMAP у личных ящиков; если не пускает — " +
			"этот ящик пока не подключить (OAuth Microsoft появится следующим этапом).",
	},
	{
		Name: "Zoho Mail", Domains: []string{"zoho.com", "zohomail.com"},
		IMAP:        Server{"imap.zoho.com", 993, SecurityTLS},
		SMTP:        Server{"smtp.zoho.com", 465, SecurityTLS},
		AppPassword: "accounts.zoho.com → Security → App Passwords",
	},
	{
		Name: "GMX", Domains: []string{"gmx.com", "gmx.net", "gmx.de"},
		IMAP: Server{"imap.gmx.com", 993, SecurityTLS},
		SMTP: Server{"mail.gmx.com", 587, SecurityStartTLS},
	},
}

// ProviderFor находит сервис по адресу. ok=false — домен свой
// (корпоративный, хостинг), настройки придётся ввести руками.
func ProviderFor(email string) (Provider, bool) {
	i := strings.LastIndexByte(email, '@')
	if i < 0 {
		return Provider{}, false
	}
	domain := strings.ToLower(strings.TrimSpace(email[i+1:]))
	for _, p := range Providers {
		for _, d := range p.Domains {
			if d == domain {
				return p, true
			}
		}
	}
	return Provider{}, false
}
