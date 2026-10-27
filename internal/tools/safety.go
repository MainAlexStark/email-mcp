// Package tools — реестр инструментов MCP-сервера и защита от
// разрушительных действий.
//
// Ключевая мысль этого пакета: сервер отдаёт языковой модели доступ
// к живой почте человека. Отправленное письмо не вернуть, удалённое
// из корзины — тоже, а письмо, ушедшее не тому адресату, — это уже
// утечка. Поэтому опасные действия закрыты независимыми заслонами:
//
//  1. Права по умолчанию — только чтение. Черновики, изменение ящика
//     и отправка — три отдельных права, каждое открывает человек:
//     переменной окружения (stdio) или галочкой на экране согласия
//     (сервис). Удачная формулировка в чате их не открывает.
//
//  2. Страховка от дорогой ошибки. Удаление и массовые операции
//     требуют confirm, письмо на много адресов — confirm_many_recipients,
//     пакет больше порога отклоняется: чем меньше писем в одном вызове,
//     тем меньше вреда от неверно понятой просьбы.
//
//  3. Ограничение размера ответа. Ответ сверх лимита клиента до модели
//     не доезжает вовсе — модель видит отказ и повторяет вызов.
package tools

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Access — какое право нужно инструменту.
type Access int

const (
	// AccessRead — чтение писем и папок.
	AccessRead Access = iota
	// AccessDrafts — черновики: создать, поправить, удалить. Ничего не
	// уходит наружу, человек увидит черновик в своей почте.
	AccessDrafts
	// AccessWrite — изменение ящика: флаги, перенос, удаление, папки.
	AccessWrite
	// AccessSend — отправка писем.
	AccessSend
)

func (a Access) String() string {
	switch a {
	case AccessDrafts:
		return "черновики"
	case AccessWrite:
		return "изменение ящика"
	case AccessSend:
		return "отправка"
	}
	return "чтение"
}

// Safety — права и пороги защиты.
type Safety struct {
	Drafts bool
	Write  bool
	Send   bool

	// MaxItemsPerWrite — сколько писем разрешено менять за один вызов.
	MaxItemsPerWrite int

	// MaxRecipients — сколько получателей (to+cc+bcc) можно указать без
	// confirm_many_recipients. Рассылка на сорок адресов по ошибке
	// модели — это сорок человек, получивших не то письмо.
	MaxRecipients int

	// MaxResponseBytes — потолок размера ответа инструмента.
	//
	// Клиент режет результат по числу токенов (обычно 25 000), и ответ
	// сверх этого не доезжает вовсе. Плотный JSON — это примерно три
	// байта на токен, поэтому потолок держится заметно ниже.
	MaxResponseBytes int
}

// DefaultSafety — осторожные значения по умолчанию: только чтение.
func DefaultSafety() Safety {
	return Safety{
		MaxItemsPerWrite: 100,
		MaxRecipients:    10,
		MaxResponseBytes: 40_000,
	}
}

// Mode — права одной строкой, для статуса и журналов.
func (s Safety) Mode() string {
	parts := []string{"чтение"}
	if s.Drafts {
		parts = append(parts, "черновики")
	}
	if s.Write {
		parts = append(parts, "изменение")
	}
	if s.Send {
		parts = append(parts, "отправка")
	}
	return strings.Join(parts, " + ")
}

// Allows — есть ли право.
func (s Safety) Allows(a Access) bool {
	switch a {
	case AccessDrafts:
		return s.Drafts
	case AccessWrite:
		return s.Write
	case AccessSend:
		return s.Send
	}
	return true
}

// ErrAccessDenied — инструменту нужно право, которого у подключения нет.
type ErrAccessDenied struct {
	Tool   string
	Access Access
}

var (
	accessEnv   = map[Access]string{AccessDrafts: "MAIL_ALLOW_DRAFTS", AccessWrite: "MAIL_ALLOW_WRITES", AccessSend: "MAIL_ALLOW_SEND"}
	accessScope = map[Access]string{AccessDrafts: "«Черновики»", AccessWrite: "«Изменение ящика»", AccessSend: "«Отправка»"}
)

func (e ErrAccessDenied) Error() string {
	// Сообщение покрывает оба транспорта: инструмент один, а чинить
	// надо разное. Не назвать оба варианта — значит отправить человека
	// править не то место.
	return fmt.Sprintf(
		"Инструменту %s нужно право «%s», а у этого подключения его нет.\n\n"+
			"Это защита по умолчанию: права открывает человек в настройках,\n"+
			"а не удачная формулировка в разговоре.\n\n"+
			"Если сервер запущен локально (stdio) — добавьте в его конфигурацию:\n"+
			"    %s=true\n"+
			"и перезапустите Claude.\n\n"+
			"Если сервер подключён как сервис — при подключении право %s не было\n"+
			"выдано. Удалите коннектор в Claude, добавьте заново и отметьте его на\n"+
			"экране согласия (для API-токена — выпустите токен с этим правом).\n\n"+
			"Текущие права подключения показывает mail_status. Чтение работает как обычно.",
		e.Tool, e.Access, accessEnv[e.Access], accessScope[e.Access])
}

// Check пропускает вызов, если право есть.
func (s Safety) Check(tool string, a Access) error {
	if !s.Allows(a) {
		return ErrAccessDenied{Tool: tool, Access: a}
	}
	return nil
}

// CheckBatchSize ограничивает размер пачки на запись.
func (s Safety) CheckBatchSize(n int) error {
	if s.MaxItemsPerWrite > 0 && n > s.MaxItemsPerWrite {
		return fmt.Errorf(
			"за один вызов разрешено менять не более %d писем, запрошено %d. "+
				"Разбейте на несколько вызовов — так ошибка затронет меньше писем",
			s.MaxItemsPerWrite, n)
	}
	return nil
}

// CheckRecipients останавливает письмо на много адресов без явного
// подтверждения.
func (s Safety) CheckRecipients(n int, confirmed bool) error {
	if s.MaxRecipients <= 0 || confirmed || n <= s.MaxRecipients {
		return nil
	}
	return fmt.Errorf(
		"у письма %d получателей — больше порога %d, отправка остановлена.\n\n"+
			"Покажите человеку полный список адресов. Если он подтвердил, что письмо "+
			"действительно должно уйти всем, повторите вызов с confirm_many_recipients: true.",
		n, s.MaxRecipients)
}

// TrimResponse укорачивает слишком длинный ответ, объясняя, что
// произошло.
//
// JSON укорачивается по элементам — так, чтобы наружу вышел валидный
// документ с отметкой об обрезке (см. trim.go). Байтовый срез остаётся
// только для ответов, которые не JSON: там резать по элементам нечего,
// зато важно, чтобы обрубок нельзя было принять за полные данные.
func (s Safety) TrimResponse(body string) string {
	if s.MaxResponseBytes <= 0 || len(body) <= s.MaxResponseBytes {
		return body
	}

	// Хвост с объяснением сам занимает место, и без запаса под него
	// обрезанный ответ снова оказывается длиннее потолка.
	const noteBudget = 400
	limit := s.MaxResponseBytes - noteBudget
	if limit < 0 {
		limit = 0
	}

	if trimmed, ok := trimJSON(body, limit); ok {
		return trimmed
	}

	if limit > len(body) {
		limit = len(body)
	}
	// Срез по байтам легко приходится на середину кириллической буквы,
	// а битый UTF-8 ломает уже не смысл ответа, а сам протокол.
	for limit > 0 && !utf8.ValidString(body[:limit]) {
		limit--
	}
	return body[:limit] + fmt.Sprintf(
		"\n\n[…ответ обрезан на %d байтах из %d — это фрагмент, а не документ, "+
			"и разбирать его как целое нельзя. Повторный вызов с теми же аргументами "+
			"вернёт ровно то же самое: сузьте выборку — меньший limit, body_max_chars, "+
			"фильтр по отправителю или дате.]",
		limit, len(body))
}
