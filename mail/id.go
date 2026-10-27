package mail

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/emersion/go-imap/v2"
)

// MessageID — устойчивый адрес письма: imap:{account}:{mailbox}:{uidvalidity}:{uid}.
//
// Формат взят из исходного mail-mcp без изменений: по нему ходят уже
// написанные промпты и скрипты. Имя папки может содержать двоеточия
// (Projects:2026:Q1) — поэтому числа отрезаются с конца, а всё, что
// между account и ними, считается папкой.
//
// UIDVALIDITY внутри нужен затем, чтобы письмо, адрес которого сохранили
// вчера, не оказалось сегодня другим письмом: сервер, пересоздавший
// папку, меняет UIDVALIDITY, и старый идентификатор честно перестаёт
// работать вместо того, чтобы молча указывать на чужое письмо.
type MessageID struct {
	Account     string
	Mailbox     string
	UIDValidity uint32
	UID         imap.UID
}

// String кодирует идентификатор.
func (m MessageID) String() string {
	return fmt.Sprintf("imap:%s:%s:%d:%d", m.Account, m.Mailbox, m.UIDValidity, m.UID)
}

// ParseMessageID разбирает идентификатор.
func ParseMessageID(raw string) (MessageID, error) {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	if len(parts) < 5 || parts[0] != "imap" {
		return MessageID{}, inputf("message_id %q не в формате imap:{account}:{mailbox}:{uidvalidity}:{uid} — "+
			"возьмите его из imap_search_messages", raw)
	}
	uid, err := strconv.ParseUint(parts[len(parts)-1], 10, 32)
	if err != nil || uid == 0 {
		return MessageID{}, inputf("message_id %q: последний сегмент (uid) должен быть положительным числом", raw)
	}
	uv, err := strconv.ParseUint(parts[len(parts)-2], 10, 32)
	if err != nil {
		return MessageID{}, inputf("message_id %q: предпоследний сегмент (uidvalidity) должен быть числом", raw)
	}
	mbox := strings.Join(parts[2:len(parts)-2], ":")
	if mbox == "" {
		return MessageID{}, inputf("message_id %q: пустое имя папки", raw)
	}
	if !ValidID(parts[1]) {
		return MessageID{}, inputf("message_id %q: недопустимое имя ящика", raw)
	}
	return MessageID{Account: parts[1], Mailbox: mbox, UIDValidity: uint32(uv), UID: imap.UID(uid)}, nil
}

// ParseMessageIDFor разбирает идентификатор и сверяет ящик: письмо из
// одного ящика, переданное в вызов для другого, — почти всегда путаница
// модели, и выполнять её молча нельзя.
func ParseMessageIDFor(raw, account string) (MessageID, error) {
	id, err := ParseMessageID(raw)
	if err != nil {
		return id, err
	}
	if id.Account != account {
		return id, inputf("message_id относится к ящику %q, а вызов — к %q. Передайте account_id=%q",
			id.Account, account, id.Account)
	}
	return id, nil
}

// checkUIDValidity — папку пересоздали, и uid из идентификатора теперь
// может указывать на другое письмо.
func checkUIDValidity(id MessageID, current uint32) error {
	if current != 0 && id.UIDValidity != current {
		return &Error{Kind: KindNotFound, Msg: fmt.Sprintf(
			"папка %q изменилась с момента поиска (uidvalidity %d → %d): идентификатор устарел, найдите письмо заново",
			id.Mailbox, id.UIDValidity, current)}
	}
	return nil
}
