package mail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-smtp"
)

// Kind — класс отказа. По нему выбирается совет человеку: на неверный
// пароль надо идти в настройки ящика, на обрыв сети — проверять
// маршрут, и совет не из того класса стоит вечера.
type Kind string

const (
	KindInput    Kind = "invalid_input"
	KindNotFound Kind = "not_found"
	KindAuth     Kind = "auth_failed"
	KindNetwork  Kind = "network"
	KindTLS      Kind = "tls"
	KindServer   Kind = "server"
	KindTimeout  Kind = "timeout"
)

// Error — ошибка операции с ящиком.
type Error struct {
	Kind Kind
	Msg  string
	// Host — сервер, на котором случился отказ (для подсказки).
	Host string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil && e.Msg == "" {
		return e.Err.Error()
	}
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

func inputf(format string, a ...any) error {
	return &Error{Kind: KindInput, Msg: fmt.Sprintf(format, a...)}
}

func notFoundf(format string, a ...any) error {
	return &Error{Kind: KindNotFound, Msg: fmt.Sprintf(format, a...)}
}

// KindOf — класс ошибки; KindServer для всего нераспознанного.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindServer
}

// IsInput — ошибка во входных данных, её можно показать как есть.
func IsInput(err error) bool { return KindOf(err) == KindInput }

// classify превращает ошибку библиотеки в *Error нужного класса.
func classify(err error, host, stage string) error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	wrap := func(k Kind) error { return &Error{Kind: k, Msg: stage, Host: host, Err: err} }

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return wrap(KindTimeout)
	case errors.Is(err, context.Canceled):
		return wrap(KindTimeout)
	}

	var (
		certErr   *tls.CertificateVerificationError
		unknownCA x509.UnknownAuthorityError
		hostErr   x509.HostnameError
		recordErr tls.RecordHeaderError
	)
	if errors.As(err, &certErr) || errors.As(err, &unknownCA) || errors.As(err, &hostErr) || errors.As(err, &recordErr) {
		return wrap(KindTLS)
	}

	var imapErr *imap.Error
	if errors.As(err, &imapErr) {
		switch imapErr.Code {
		case imap.ResponseCodeAuthenticationFailed, imap.ResponseCodeAuthorizationFailed,
			imap.ResponseCodeExpired, imap.ResponseCodePrivacyRequired:
			return wrap(KindAuth)
		case imap.ResponseCodeNonExistent, imap.ResponseCodeTryCreate:
			return wrap(KindNotFound)
		}
		if stage == stageLogin {
			// Многие серверы отвечают на неверный пароль голым NO без
			// кода ответа. На этапе входа другого смысла у NO нет.
			return wrap(KindAuth)
		}
		return wrap(KindServer)
	}

	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		if smtpErr.Code == 535 || smtpErr.Code == 534 || smtpErr.Code == 530 {
			return wrap(KindAuth)
		}
		return wrap(KindServer)
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return wrap(KindTimeout)
		}
		return wrap(KindNetwork)
	}
	var opErr *net.OpError
	var dnsErr *net.DNSError
	if errors.As(err, &opErr) || errors.As(err, &dnsErr) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return wrap(KindNetwork)
	}
	return wrap(KindServer)
}

const (
	stageConnect = "подключение к серверу"
	stageLogin   = "вход в ящик"
)

// Hint — совет человеку к отказу. Пустая строка — сказать нечего.
func Hint(err error) string {
	var e *Error
	if !errors.As(err, &e) {
		return ""
	}
	switch e.Kind {
	case KindAuth:
		return authHint(e.Host)
	case KindNetwork:
		return fmt.Sprintf("Сервер %s недоступен по сети. Проверьте адрес и порт ящика; "+
			"если сервер работает, а ошибка повторяется — провайдер может блокировать "+
			"подключения с адреса сервера MCP.", hostOr(e.Host))
	case KindTimeout:
		return "Сервер не ответил вовремя. Если это поиск по большой папке — сузьте его " +
			"(last_days, from, subject); если вход — проверьте порт и режим защиты (tls/starttls)."
	case KindTLS:
		return fmt.Sprintf("Не удалось установить защищённое соединение с %s. Чаще всего перепутан "+
			"режим: на порту 993/465 нужен tls, на 143/587 — starttls.", hostOr(e.Host))
	case KindNotFound:
		return "Проверьте имя папки через imap_list_mailboxes и message_id через imap_search_messages: " +
			"после переименования папки или чистки корзины старые идентификаторы перестают работать."
	}
	return ""
}

func hostOr(h string) string {
	if h == "" {
		return "почты"
	}
	return h
}

// authHint — у крупных провайдеров обычный пароль по IMAP не пускают,
// и вслепую человек будет перебирать свой основной пароль до блокировки.
func authHint(host string) string {
	h := strings.ToLower(host)
	switch {
	case strings.Contains(h, "gmail") || strings.Contains(h, "google"):
		return "Gmail не пускает по IMAP с обычным паролем. Включите двухэтапную проверку и создайте " +
			"пароль приложения: myaccount.google.com → Безопасность → Пароли приложений."
	case strings.Contains(h, "yandex"):
		return "Яндекс требует пароль приложения: id.yandex.ru → Безопасность → Пароли приложений → Почта. " +
			"И включите доступ по IMAP: Почта → Настройки → Почтовые программы."
	case strings.Contains(h, "mail.ru") || strings.Contains(h, "bk.ru") || strings.Contains(h, "inbox.ru") || strings.Contains(h, "list.ru"):
		return "Mail.ru пускает внешние программы только с паролем приложения: " +
			"Настройки → Безопасность → Пароли для внешних приложений."
	case strings.Contains(h, "icloud") || strings.Contains(h, "me.com"):
		return "iCloud требует пароль приложения: appleid.apple.com → Вход и безопасность → Пароли приложений."
	case strings.Contains(h, "outlook") || strings.Contains(h, "office365") || strings.Contains(h, "hotmail"):
		return "Microsoft отключил вход по паролю для IMAP/SMTP у большинства ящиков. Если у вас " +
			"корпоративный ящик, спросите администратора, разрешён ли IMAP и SMTP AUTH."
	case strings.Contains(h, "rambler"):
		return "Рамблер требует включить доступ по IMAP в настройках почты: Настройки → Программы."
	}
	return "Сервер отклонил логин или пароль. Многие провайдеры требуют отдельный пароль " +
		"приложения вместо основного и отдельно включённый доступ по IMAP."
}
