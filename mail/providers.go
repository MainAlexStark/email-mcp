package mail

import "strings"

// Provider — настройки известного почтового сервиса.
type Provider struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	IMAP    Server   `json:"imap"`
	SMTP    Server   `json:"smtp"`
	// Password — какой пароль вводить и по шагам, где его взять.
	Password PasswordGuide `json:"password"`
	// Note — особенности логина и прочее, что не про пароль.
	Note string `json:"note,omitempty"`
}

// Какой пароль принимает сервис по IMAP/SMTP.
const (
	// PasswordApp — только отдельный пароль приложения, основной не пустят.
	PasswordApp = "app"
	// PasswordMain — основной пароль от ящика, но доступ надо включить.
	PasswordMain = "main"
	// PasswordNone — по паролю ящик не подключить вовсе.
	PasswordNone = "none"
)

// PasswordGuide — явная инструкция «где взять пароль». Шаги написаны
// для человека, который не знает слова IMAP: что открыть, что нажать,
// что скопировать в форму.
type PasswordGuide struct {
	Kind string `json:"kind"`
	// URL — прямая ссылка на страницу, где создают пароль (или включают доступ).
	URL   string   `json:"url,omitempty"`
	Steps []string `json:"steps"`
}

// KindLabel — короткая подпись к типу пароля для страниц.
func (g PasswordGuide) KindLabel() string {
	switch g.Kind {
	case PasswordApp:
		return "нужен пароль приложения"
	case PasswordMain:
		return "основной пароль, но доступ надо включить"
	case PasswordNone:
		return "по паролю не подключить"
	}
	return ""
}

// Summary — инструкция одной строкой: для подсказок к ошибкам и ответов Claude.
func (g PasswordGuide) Summary() string {
	s := strings.Join(g.Steps, " ")
	if g.URL != "" {
		s += " Ссылка: " + g.URL
	}
	return s
}

// Providers — сервисы, которые узнаются по домену адреса. Человеку,
// который подключает ящик, не нужно знать слова «IMAP» и «993»:
// хватит адреса и пароля приложения.
var Providers = []Provider{
	{
		Name: "Gmail", Domains: []string{"gmail.com", "googlemail.com"},
		IMAP: Server{"imap.gmail.com", 993, SecurityTLS},
		SMTP: Server{"smtp.gmail.com", 465, SecurityTLS},
		Password: PasswordGuide{
			Kind: PasswordApp,
			URL:  "https://myaccount.google.com/apppasswords",
			Steps: []string{
				"Включите двухэтапную проверку: myaccount.google.com → Безопасность → Двухэтапная аутентификация (без неё пункта с паролями приложений нет).",
				"Откройте myaccount.google.com/apppasswords, введите любое название, например «Email MCP», и нажмите «Создать».",
				"Скопируйте показанные 16 букв (пробелы можно не убирать) и вставьте в поле «Пароль приложения».",
			},
		},
	},
	{
		Name: "Яндекс Почта", Domains: []string{"yandex.ru", "ya.ru", "yandex.com", "yandex.by", "yandex.kz", "narod.ru"},
		IMAP: Server{"imap.yandex.ru", 993, SecurityTLS},
		SMTP: Server{"smtp.yandex.ru", 465, SecurityTLS},
		Password: PasswordGuide{
			Kind: PasswordApp,
			URL:  "https://id.yandex.ru/security/app-passwords",
			Steps: []string{
				"Включите доступ программам: Почта → ⚙ Все настройки → Почтовые программы → отметьте «С сервера imap.yandex.ru по протоколу IMAP» и «Пароли приложений и OAuth-токены».",
				"Откройте id.yandex.ru → Безопасность → Пароли приложений → «Создать пароль» → тип «Почта», название любое.",
				"Скопируйте пароль (он показывается один раз) и вставьте в поле «Пароль приложения».",
			},
		},
	},
	{
		Name: "Mail.ru", Domains: []string{"mail.ru", "bk.ru", "inbox.ru", "list.ru", "internet.ru"},
		IMAP: Server{"imap.mail.ru", 993, SecurityTLS},
		SMTP: Server{"smtp.mail.ru", 465, SecurityTLS},
		Password: PasswordGuide{
			Kind: PasswordApp,
			URL:  "https://account.mail.ru/user/2-step-auth/passwords/",
			Steps: []string{
				"Откройте id.mail.ru → Безопасность → Пароли для внешних приложений → «Добавить».",
				"Название любое, доступ — «Полный доступ к Почте» (без него не будет отправки по SMTP).",
				"Скопируйте пароль (показывается один раз) и вставьте в поле «Пароль приложения».",
			},
		},
	},
	{
		Name: "Рамблер", Domains: []string{"rambler.ru", "lenta.ru", "autorambler.ru", "myrambler.ru", "ro.ru"},
		IMAP: Server{"imap.rambler.ru", 993, SecurityTLS},
		SMTP: Server{"smtp.rambler.ru", 465, SecurityTLS},
		Password: PasswordGuide{
			Kind: PasswordMain,
			URL:  "https://mail.rambler.ru/settings/mailapps",
			Steps: []string{
				"Откройте Рамблер Почту → Настройки → Почтовые программы и включите «Доступ к почтовому ящику с помощью почтовых клиентов».",
				"В поле «Пароль приложения» введите обычный пароль от Рамблер ID — отдельного пароля приложения Рамблер не выдаёт.",
			},
		},
	},
	{
		Name: "iCloud", Domains: []string{"icloud.com", "me.com", "mac.com"},
		IMAP: Server{"imap.mail.me.com", 993, SecurityTLS},
		SMTP: Server{"smtp.mail.me.com", 587, SecurityStartTLS},
		Password: PasswordGuide{
			Kind: PasswordApp,
			URL:  "https://account.apple.com/account/manage",
			Steps: []string{
				"Нужна двухфакторная аутентификация Apple ID (обычно уже включена).",
				"Откройте account.apple.com → Вход и безопасность → Пароли приложений → «+», название любое.",
				"Скопируйте пароль вида xxxx-xxxx-xxxx-xxxx и вставьте в поле «Пароль приложения».",
			},
		},
		Note: "Логин — полный адрес @icloud.com, даже если Apple ID на другой почте.",
	},
	{
		Name: "Outlook.com", Domains: []string{"outlook.com", "hotmail.com", "live.com", "msn.com"},
		IMAP: Server{"outlook.office365.com", 993, SecurityTLS},
		SMTP: Server{"smtp-mail.outlook.com", 587, SecurityStartTLS},
		Password: PasswordGuide{
			Kind: PasswordNone,
			Steps: []string{
				"Microsoft отключил вход по паролю (и по паролям приложений) для IMAP/SMTP личных ящиков — подходящего пароля не существует.",
				"Такой ящик подключится, когда появится вход через Microsoft (OAuth). Корпоративный ящик Microsoft 365 — только если администратор разрешил IMAP и SMTP AUTH.",
			},
		},
	},
	{
		Name: "Zoho Mail", Domains: []string{"zoho.com", "zohomail.com"},
		IMAP: Server{"imap.zoho.com", 993, SecurityTLS},
		SMTP: Server{"smtp.zoho.com", 465, SecurityTLS},
		Password: PasswordGuide{
			Kind: PasswordApp,
			URL:  "https://accounts.zoho.com/home#security/app_password",
			Steps: []string{
				"Включите IMAP: Zoho Mail → ⚙ Settings → Mail Accounts → IMAP Access.",
				"Откройте accounts.zoho.com → Security → App Passwords → «Generate New Password», название любое.",
				"Скопируйте пароль и вставьте в поле «Пароль приложения». Без двухфакторной защиты Zoho примет и основной пароль, но лучше отдельный.",
			},
		},
	},
	{
		Name: "GMX", Domains: []string{"gmx.com", "gmx.net", "gmx.de"},
		IMAP: Server{"imap.gmx.com", 993, SecurityTLS},
		SMTP: Server{"mail.gmx.com", 587, SecurityStartTLS},
		Password: PasswordGuide{
			Kind: PasswordMain,
			Steps: []string{
				"Включите доступ: GMX Mail → Settings → POP3 & IMAP → «Enable access to this account via POP3 and IMAP» → Save.",
				"В поле «Пароль приложения» введите обычный пароль от GMX.",
			},
		},
	},
}

// CustomDomainGuide — когда домен свой (корпоративный, хостинг).
var CustomDomainGuide = PasswordGuide{
	Kind: PasswordMain,
	Steps: []string{
		"Обычно это тот же пароль, которым вы входите в веб-почту этого ящика.",
		"Если почта на Яндекс 360, Google Workspace или Mail.ru для бизнеса — пароль приложения создаётся так же, как для обычного ящика этого сервиса.",
		"Адреса серверов и разрешён ли IMAP — спросите у администратора почты или в справке хостинга.",
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

// ProviderForHost находит сервис по адресу IMAP/SMTP-сервера — для
// подсказки к отказу, когда известен только сервер.
func ProviderForHost(host string) (Provider, bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return Provider{}, false
	}
	// Точное совпадение, затем родительский домен: imap.ya.ru → ya.ru,
	// smtp.office365.com → office365.com (та же почта Microsoft).
	parent := h
	if i := strings.IndexByte(h, '.'); i >= 0 {
		parent = h[i+1:]
	}
	for _, p := range Providers {
		if h == p.IMAP.Host || h == p.SMTP.Host {
			return p, true
		}
	}
	for _, p := range Providers {
		if parent == hostParent(p.IMAP.Host) || parent == hostParent(p.SMTP.Host) {
			return p, true
		}
		for _, d := range p.Domains {
			if parent == d {
				return p, true
			}
		}
	}
	return Provider{}, false
}

func hostParent(h string) string {
	if i := strings.IndexByte(h, '.'); i >= 0 {
		return h[i+1:]
	}
	return h
}
