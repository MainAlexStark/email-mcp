package web

import (
	"bytes"
	"strings"
	"testing"

	"github.com/MainAlexStark/email-mcp/mail"
)

// Форма ящика собирается без БД: инструкции для всех сервисов на месте,
// инструкция найденного сервиса — сверху, без повтора в списке.
func TestMailboxFormShowsPasswordGuides(t *testing.T) {
	var empty bytes.Buffer
	if err := pages["mailbox_form"].Execute(&empty, mailboxFormView{First: true}); err != nil {
		t.Fatal(err)
	}
	for _, p := range mail.Providers {
		if !strings.Contains(empty.String(), p.Name) || !strings.Contains(empty.String(), p.Password.Steps[0][:20]) {
			t.Fatalf("нет инструкции для %s", p.Name)
		}
	}
	if strings.Contains(empty.String(), "open>") {
		t.Fatal("без адреса ни одна инструкция не должна быть раскрыта")
	}

	p, _ := mail.ProviderFor("me@yandex.ru")
	var found bytes.Buffer
	if err := pages["mailbox_form"].Execute(&found, mailboxFormView{Provider: &p}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(found.String(), "Яндекс Почта — нужен пароль приложения") ||
		strings.Count(found.String(), "id.yandex.ru → Безопасность → Пароли приложений") != 1 {
		t.Fatalf("инструкция Яндекса не сверху или повторяется:\n%s", found.String())
	}
}
