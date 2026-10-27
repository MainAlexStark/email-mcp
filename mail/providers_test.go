package mail

import (
	"strings"
	"testing"
)

// У каждого сервиса должна быть явная инструкция: тип пароля и шаги.
func TestEveryProviderHasPasswordGuide(t *testing.T) {
	for _, p := range Providers {
		if p.Password.KindLabel() == "" {
			t.Errorf("%s: неизвестный тип пароля %q", p.Name, p.Password.Kind)
		}
		if len(p.Password.Steps) == 0 {
			t.Errorf("%s: нет шагов «где взять пароль»", p.Name)
		}
		if u := p.Password.URL; u != "" && !strings.HasPrefix(u, "https://") {
			t.Errorf("%s: ссылка не https: %s", p.Name, u)
		}
	}
}

// Подсказка к отказу входа — та же инструкция, что на странице.
func TestAuthHintUsesProviderGuide(t *testing.T) {
	for host, want := range map[string]string{
		"imap.gmail.com":     "myaccount.google.com/apppasswords",
		"smtp.yandex.ru":     "id.yandex.ru",
		"imap.ya.ru":         "id.yandex.ru",
		"imap.mail.ru":       "Полный доступ к Почте",
		"imap.rambler.ru":    "Почтовые программы",
		"imap.mail.me.com":   "account.apple.com",
		"smtp.office365.com": "Microsoft",
		"imap.zoho.com":      "App Passwords",
		"imap.example.org":   "пароль",
	} {
		if h := authHint(host); !strings.Contains(h, want) {
			t.Errorf("%s: в подсказке нет %q: %s", host, want, h)
		}
	}
}
