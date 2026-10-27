// Package mail — клиент почтового ящика: IMAP для чтения и папок,
// SMTP для отправки. Ничего не знает про MCP и инструменты: это
// самостоятельная библиотека, которую можно взять отдельно.
//
// Подключение открывается на одну операцию и закрывается после неё.
// Держать долгие IMAP-сессии на каждого пользователя сервиса значило бы
// упереться в лимиты провайдеров (Gmail даёт 15 одновременных
// соединений на ящик) и разбираться с обрывами посреди простоя. Цена —
// лишнее рукопожатие TLS на вызов, и для инструмента, который зовёт
// модель раз в несколько секунд, она незаметна.
package mail

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Security — как защищено соединение с сервером.
type Security string

const (
	// SecurityTLS — TLS с первого байта (IMAP 993, SMTP 465).
	SecurityTLS Security = "tls"
	// SecurityStartTLS — открытое соединение с переходом на TLS (SMTP 587, IMAP 143).
	SecurityStartTLS Security = "starttls"
	// SecurityNone — без шифрования. Только для локальной отладки:
	// пароль уходит открытым текстом.
	SecurityNone Security = "none"
)

// ParseSecurity разбирает значение из конфигурации. Пусто — TLS.
func ParseSecurity(s string) (Security, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "tls", "ssl", "true", "1", "yes":
		return SecurityTLS, nil
	case "starttls", "start_tls":
		return SecurityStartTLS, nil
	case "none", "plain", "false", "0", "no", "insecure":
		return SecurityNone, nil
	}
	return "", fmt.Errorf("неизвестный режим защиты %q: допустимо tls, starttls или none", s)
}

// Server — адрес почтового сервера.
type Server struct {
	Host     string
	Port     int
	Security Security
}

// Addr — host:port для dial.
func (s Server) Addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }

// Configured — задан ли сервер вообще.
func (s Server) Configured() bool { return s.Host != "" }

// Account — один почтовый ящик.
type Account struct {
	// ID — короткое имя ящика, которое видит модель (account_id).
	// В сервисе уникально в пределах пользователя.
	ID string

	// Email — адрес отправителя (From).
	Email string
	// DisplayName — имя в From, может быть пустым.
	DisplayName string

	IMAP Server
	// SMTP может быть не задан: тогда ящик только для чтения.
	SMTP Server

	Username string
	Password string

	// SMTPUsername и SMTPPassword — если вход на SMTP отличается от
	// IMAP (общий ящик, куда отправляют под личной учётной записью).
	// Пусто — те же, что для IMAP.
	SMTPUsername string
	SMTPPassword string

	// SaveSent — класть ли копию отправленного в «Отправленные».
	// nil — решить по провайдеру (см. ShouldSaveSent).
	SaveSent *bool

	// Timeout — потолок на одну операцию. 0 — DefaultTimeout.
	Timeout time.Duration
}

// DefaultTimeout — сколько ждать одну операцию с сервером.
//
// Две минуты, а не тридцать секунд: поиск по ящику на 100 тысяч писем
// у Mail.ru идёт десятки секунд, и обрыв на середине оставил бы модель
// без ответа и с желанием повторить тот же тяжёлый запрос.
const DefaultTimeout = 2 * time.Minute

func (a *Account) timeout() time.Duration {
	if a.Timeout > 0 {
		return a.Timeout
	}
	return DefaultTimeout
}

// accountIDPattern — то же, что в исходном mail-mcp: идентификатор
// попадает в message_id через двоеточия и в имена переменных окружения.
var accountIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidID проверяет идентификатор ящика.
func ValidID(id string) bool { return accountIDPattern.MatchString(id) }

// Validate проверяет, что ящик описан достаточно, чтобы к нему
// подключиться. Ошибки — для человека, который заполняет форму.
func (a *Account) Validate() error {
	if !ValidID(a.ID) {
		return inputf("имя ящика %q: только латиница, цифры, _ и -, до 64 символов", a.ID)
	}
	if a.IMAP.Host == "" {
		return inputf("не задан IMAP-сервер")
	}
	if err := validHost(a.IMAP.Host); err != nil {
		return err
	}
	if a.IMAP.Port <= 0 || a.IMAP.Port > 65535 {
		return inputf("порт IMAP %d вне диапазона 1–65535", a.IMAP.Port)
	}
	if a.SMTP.Host != "" {
		if err := validHost(a.SMTP.Host); err != nil {
			return err
		}
		if a.SMTP.Port <= 0 || a.SMTP.Port > 65535 {
			return inputf("порт SMTP %d вне диапазона 1–65535", a.SMTP.Port)
		}
	}
	if a.Username == "" || a.Password == "" {
		return inputf("нужны логин и пароль ящика")
	}
	if a.Email != "" {
		if _, err := ParseAddress(a.Email); err != nil {
			return inputf("адрес отправителя %q не похож на почтовый адрес", a.Email)
		}
	}
	return nil
}

func validHost(h string) error {
	if strings.ContainsAny(h, " \t\r\n/:@") || len(h) > 253 {
		return inputf("адрес сервера %q: нужно только имя хоста, без протокола и порта", h)
	}
	return nil
}

// Sender — адрес From: Email, а если он не задан — логин, когда тот
// похож на адрес (у большинства провайдеров логин и есть адрес).
func (a *Account) Sender() string {
	if a.Email != "" {
		return a.Email
	}
	if strings.Contains(a.Username, "@") {
		return a.Username
	}
	return ""
}

// ShouldSaveSent решает, класть ли копию отправленного в «Отправленные».
//
// Gmail, Яндекс и Mail.ru сохраняют копию сами, и наша вторая копия
// легла бы дублем (Zoho к тому же их не схлопывает). Office 365 по SMTP
// и обычные хостинги не сохраняют — без нашей копии отправленное
// письмо пропало бы из истории.
func (a *Account) ShouldSaveSent() bool {
	if a.SaveSent != nil {
		return *a.SaveSent
	}
	h := strings.ToLower(a.SMTP.Host)
	for _, auto := range []string{"gmail.com", "googlemail.com", "zoho.", "yandex.", "mail.ru", "icloud.com", "me.com"} {
		if strings.Contains(h, auto) {
			return false
		}
	}
	return true
}
