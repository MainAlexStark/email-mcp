package tools

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/MainAlexStark/email-mcp/mail"
)

// Args — аргументы вызова как их прислала модель.
//
// Модель путает типы: число присылает строкой, одиночный адрес — не
// массивом, а строкой, true — как "true". Отказывать на это ошибкой
// значит заставлять её угадывать со второй попытки, поэтому разбор
// прощает очевидное и ругается только на бессмысленное.
type Args map[string]any

func inputf(format string, a ...any) error {
	return &mail.Error{Kind: mail.KindInput, Msg: fmt.Sprintf(format, a...)}
}

// Has — поле задано и не null.
func (a Args) Has(k string) bool {
	v, ok := a[k]
	return ok && v != nil
}

// Str — строковое поле без пробелов по краям.
func (a Args) Str(k string) string {
	switch v := a[k].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

// Raw — строка как есть (тело письма: пробелы по краям значимы).
func (a Args) Raw(k string) string {
	s, _ := a[k].(string)
	return s
}

// Bool — булево поле; строки "true"/"1" тоже считаются.
func (a Args) Bool(k string) bool {
	switch v := a[k].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1" || v == "yes"
	case float64:
		return v == 1
	}
	return false
}

// Int — целое в границах. Значение вне границ приводится к ближайшей:
// отказ на «покажи сто писем» при потолке 50 — плохой ответ на
// разумную просьбу.
func (a Args) Int(k string, def, min, max int) (int, error) {
	if !a.Has(k) {
		return def, nil
	}
	var n int
	switch v := a[k].(type) {
	case float64:
		if v != math.Trunc(v) {
			return 0, inputf("%s должен быть целым числом", k)
		}
		n = int(v)
	case string:
		p, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, inputf("%s должен быть числом, получено %q", k, v)
		}
		n = p
	default:
		return 0, inputf("%s должен быть числом", k)
	}
	if n < min {
		n = min
	}
	if n > max {
		n = max
	}
	return n, nil
}

// Strings — список строк; одиночная строка тоже принимается, строка
// через запятую — нет (адрес «Иванов, Пётр <p@x.ru>» содержит запятую).
func (a Args) Strings(k string) ([]string, error) {
	switch v := a[k].(type) {
	case nil:
		return nil, nil
	case string:
		if s := strings.TrimSpace(v); s != "" {
			return []string{s}, nil
		}
		return nil, nil
	case []any:
		out := make([]string, 0, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, inputf("%s[%d] должен быть строкой", k, i)
			}
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	}
	return nil, inputf("%s должен быть массивом строк", k)
}

// Objects — список объектов (вложения).
func (a Args) Objects(k string) ([]Args, error) {
	switch v := a[k].(type) {
	case nil:
		return nil, nil
	case []any:
		out := make([]Args, 0, len(v))
		for i, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, inputf("%s[%d] должен быть объектом", k, i)
			}
			out = append(out, Args(m))
		}
		return out, nil
	}
	return nil, inputf("%s должен быть массивом объектов", k)
}

// messageID разбирает message_id и сверяет его с account_id. Пустой
// account_id берётся из самого идентификатора: модели не нужно
// повторять то, что уже зашито в id.
func (a Args) messageID(key string) (mail.MessageID, error) {
	raw := a.Str(key)
	if raw == "" {
		return mail.MessageID{}, inputf("нужен %s — возьмите его из imap_search_messages", key)
	}
	if acc := a.Str("account_id"); acc != "" {
		return mail.ParseMessageIDFor(raw, acc)
	}
	return mail.ParseMessageID(raw)
}

// criteria — условия поиска из аргументов.
func (a Args) criteria() (mail.Criteria, error) {
	days, err := a.Int("last_days", 0, 0, 3650)
	if err != nil {
		return mail.Criteria{}, err
	}
	c := mail.Criteria{
		Query:           a.Str("query"),
		From:            a.Str("from"),
		To:              a.Str("to"),
		Subject:         a.Str("subject"),
		ThreadMessageID: a.Str("thread_message_id"),
		UnreadOnly:      a.Bool("unread_only"),
		LastDays:        days,
		StartDate:       a.Str("start_date"),
		EndDate:         a.Str("end_date"),
	}
	return c, c.Validate()
}
