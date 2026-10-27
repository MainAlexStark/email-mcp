// Package mailboxes — ящики пользователей сервиса: проверка входа при
// подключении, шифрование пароля и сборка mail.Account для запроса.
package mailboxes

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MainAlexStark/email-mcp/internal/pgstore"
	"github.com/MainAlexStark/email-mcp/internal/secure"
	"github.com/MainAlexStark/email-mcp/mail"
)

// Store — то, что сервису нужно от базы.
type Store interface {
	AddMailbox(ctx context.Context, m pgstore.Mailbox) (pgstore.Mailbox, error)
	UpdateMailbox(ctx context.Context, m pgstore.Mailbox) error
	Mailbox(ctx context.Context, userID, mailboxID int64) (pgstore.Mailbox, error)
	Mailboxes(ctx context.Context, userID int64) ([]pgstore.Mailbox, error)
	SetMailboxCheck(ctx context.Context, mailboxID int64, checkErr string) error
}

// Service — ящики и их проверка.
type Service struct {
	store  Store
	cipher *secure.Cipher
	opts   []mail.Option

	// AllowPlaintext разрешает ящики без TLS. Выключено: пароль ушёл бы
	// через интернет открытым текстом. Включается вместе с
	// MAIL_ALLOW_PRIVATE_HOSTS — для своего сервера в той же сети.
	AllowPlaintext bool
}

// New создаёт сервис. opts применяются ко всем клиентам ящиков
// (запрет внутренних адресов, TLS в тестах).
func New(store Store, cipher *secure.Cipher, opts ...mail.Option) *Service {
	return &Service{store: store, cipher: cipher, opts: opts}
}

// Options — настройки клиентов ящиков (для реестра инструментов).
func (s *Service) Options() []mail.Option { return s.opts }

// InputError — ошибка во введённых данных, её показывают человеку как есть.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

func inputErr(format string, a ...any) error { return &InputError{Msg: fmt.Sprintf(format, a...)} }

// Form — то, что человек ввёл в кабинете.
type Form struct {
	Name         string
	Email        string
	DisplayName  string
	IMAPHost     string
	IMAPPort     string
	IMAPSecurity string
	SMTPHost     string
	SMTPPort     string
	SMTPSecurity string
	Username     string
	Password     string
}

// Autofill дополняет пустые поля по известному провайдеру. Возвращает
// найденного провайдера, чтобы кабинет мог подсказать про пароль
// приложения.
func (f *Form) Autofill() (mail.Provider, bool) {
	f.Email = strings.TrimSpace(f.Email)
	p, ok := mail.ProviderFor(f.Email)
	if ok {
		if f.IMAPHost == "" {
			f.IMAPHost, f.IMAPPort, f.IMAPSecurity = p.IMAP.Host, strconv.Itoa(p.IMAP.Port), string(p.IMAP.Security)
		}
		if f.SMTPHost == "" {
			f.SMTPHost, f.SMTPPort, f.SMTPSecurity = p.SMTP.Host, strconv.Itoa(p.SMTP.Port), string(p.SMTP.Security)
		}
	}
	if f.Username == "" {
		f.Username = f.Email
	}
	if f.Name == "" {
		f.Name = suggestName(f.Email)
	}
	return p, ok
}

// suggestName — account_id из адреса: alex.stark@yandex.ru → yandex.
// Модель видит его в каждом вызове, и короткое имя провайдера
// читается лучше номера.
func suggestName(email string) string {
	i := strings.LastIndexByte(email, '@')
	if i < 0 {
		return "main"
	}
	host := email[i+1:]
	if j := strings.IndexByte(host, '.'); j > 0 {
		host = host[:j]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(host) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "main"
	}
	return b.String()
}

func parsePort(s string, def int, what string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 65535 {
		return 0, inputErr("Порт %s — число от 1 до 65535.", what)
	}
	return n, nil
}

// account собирает mail.Account из формы и проверяет его.
func (f Form) account() (mail.Account, error) {
	var acc mail.Account
	acc.ID = strings.TrimSpace(f.Name)
	acc.Email = strings.TrimSpace(f.Email)
	acc.DisplayName = strings.TrimSpace(f.DisplayName)
	acc.Username = strings.TrimSpace(f.Username)
	acc.Password = f.Password
	if utf8.RuneCountInString(acc.DisplayName) > 80 {
		return acc, inputErr("Имя отправителя длиннее 80 символов.")
	}

	sec, err := mail.ParseSecurity(f.IMAPSecurity)
	if err != nil {
		return acc, inputErr("IMAP: %v", err)
	}
	defPort := 993
	if sec != mail.SecurityTLS {
		defPort = 143
	}
	port, err := parsePort(f.IMAPPort, defPort, "IMAP")
	if err != nil {
		return acc, err
	}
	acc.IMAP = mail.Server{Host: strings.ToLower(strings.TrimSpace(f.IMAPHost)), Port: port, Security: sec}

	if h := strings.ToLower(strings.TrimSpace(f.SMTPHost)); h != "" {
		sec, err := mail.ParseSecurity(f.SMTPSecurity)
		if err != nil {
			return acc, inputErr("SMTP: %v", err)
		}
		defPort := 465
		if sec != mail.SecurityTLS {
			defPort = 587
		}
		port, err := parsePort(f.SMTPPort, defPort, "SMTP")
		if err != nil {
			return acc, err
		}
		acc.SMTP = mail.Server{Host: h, Port: port, Security: sec}
	}
	if err := acc.Validate(); err != nil {
		return acc, inputErr("%s", err.Error())
	}
	if acc.Sender() == "" {
		return acc, inputErr("Укажите адрес ящика — он нужен как адрес отправителя.")
	}
	return acc, nil
}

// Verify входит в IMAP (и SMTP, если задан). Сообщение об отказе — для
// человека, с советом про пароль приложения.
func (s *Service) Verify(ctx context.Context, acc mail.Account) error {
	if !s.AllowPlaintext && (acc.IMAP.Security == mail.SecurityNone || acc.SMTP.Security == mail.SecurityNone) {
		return inputErr("Соединение без шифрования не поддерживается: пароль ушёл бы открытым текстом. " +
			"Выберите tls или starttls.")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	acc.Timeout = 30 * time.Second
	c := mail.New(acc, s.opts...)
	if _, err := c.VerifyIMAP(ctx); err != nil {
		return humanize("IMAP", err)
	}
	if acc.SMTP.Configured() {
		if _, err := c.VerifySMTP(ctx); err != nil {
			return humanize("SMTP", err)
		}
	}
	return nil
}

func humanize(proto string, err error) error {
	msg := fmt.Sprintf("%s: %v", proto, err)
	if h := mail.Hint(err); h != "" {
		msg += ". " + h
	}
	if mail.IsInput(err) {
		return inputErr("%s", msg)
	}
	switch mail.KindOf(err) {
	case mail.KindAuth, mail.KindNetwork, mail.KindTLS, mail.KindTimeout, mail.KindNotFound:
		return inputErr("%s", msg)
	}
	return errors.New(msg)
}

// Connect проверяет вход и, если он прошёл, сохраняет ящик. Нерабочий
// пароль не сохраняется: человек узнаёт о проблеме сейчас, а не в чате
// с Claude через неделю.
func (s *Service) Connect(ctx context.Context, userID int64, f Form) (pgstore.Mailbox, error) {
	f.Autofill()
	acc, err := f.account()
	if err != nil {
		return pgstore.Mailbox{}, err
	}
	if err := s.Verify(ctx, acc); err != nil {
		return pgstore.Mailbox{}, err
	}
	enc, err := s.cipher.Encrypt([]byte(acc.Password), aad(userID, acc.Username))
	if err != nil {
		return pgstore.Mailbox{}, err
	}
	now := time.Now()
	m, err := s.store.AddMailbox(ctx, toRow(userID, acc, enc, &now))
	if errors.Is(err, pgstore.ErrMailboxExists) {
		return pgstore.Mailbox{}, inputErr("Ящик с именем %q уже подключён — выберите другое имя.", acc.ID)
	}
	return m, err
}

// Update меняет настройки ящика. Пустой пароль — оставить прежний.
func (s *Service) Update(ctx context.Context, userID, mailboxID int64, f Form) error {
	row, err := s.store.Mailbox(ctx, userID, mailboxID)
	if err != nil {
		return err
	}
	if f.Password == "" {
		old, err := s.decrypt(row)
		if err != nil {
			return err
		}
		f.Password = old
	}
	f.Name = row.Name // имя — это account_id в уже написанных промптах, его не меняем
	f.Autofill()
	acc, err := f.account()
	if err != nil {
		return err
	}
	if err := s.Verify(ctx, acc); err != nil {
		return err
	}
	enc, err := s.cipher.Encrypt([]byte(acc.Password), aad(userID, acc.Username))
	if err != nil {
		return err
	}
	upd := toRow(userID, acc, enc, nil)
	upd.ID = mailboxID
	return s.store.UpdateMailbox(ctx, upd)
}

func toRow(userID int64, acc mail.Account, enc []byte, checked *time.Time) pgstore.Mailbox {
	return pgstore.Mailbox{
		UserID: userID, Name: acc.ID, Email: acc.Email, DisplayName: acc.DisplayName,
		IMAPHost: acc.IMAP.Host, IMAPPort: acc.IMAP.Port, IMAPSecurity: string(acc.IMAP.Security),
		SMTPHost: acc.SMTP.Host, SMTPPort: acc.SMTP.Port, SMTPSecurity: string(acc.SMTP.Security),
		Username: acc.Username, PasswordEnc: enc, CheckedAt: checked,
	}
}

// Check перепроверяет вход и записывает итог.
func (s *Service) Check(ctx context.Context, userID, mailboxID int64) error {
	row, err := s.store.Mailbox(ctx, userID, mailboxID)
	if err != nil {
		return err
	}
	acc, err := s.Account(row)
	if err != nil {
		return err
	}
	checkErr := s.Verify(ctx, acc)
	msg := ""
	if checkErr != nil {
		msg = checkErr.Error()
	}
	if err := s.store.SetMailboxCheck(ctx, row.ID, msg); err != nil {
		return err
	}
	return checkErr
}

// Account расшифровывает строку базы в mail.Account.
func (s *Service) Account(row pgstore.Mailbox) (mail.Account, error) {
	pass, err := s.decrypt(row)
	if err != nil {
		return mail.Account{}, err
	}
	imapSec, _ := mail.ParseSecurity(row.IMAPSecurity)
	acc := mail.Account{
		ID: row.Name, Email: row.Email, DisplayName: row.DisplayName,
		IMAP:     mail.Server{Host: row.IMAPHost, Port: row.IMAPPort, Security: imapSec},
		Username: row.Username, Password: pass,
	}
	if row.SMTPHost != "" {
		smtpSec, _ := mail.ParseSecurity(row.SMTPSecurity)
		acc.SMTP = mail.Server{Host: row.SMTPHost, Port: row.SMTPPort, Security: smtpSec}
	}
	return acc, nil
}

// Accounts — ящики подключения: один (mailboxID > 0) или все.
//
// Строки читаются из базы на каждый запрос: удалённый ящик перестаёт
// работать сразу, сменённый пароль подхватывается без перезапуска.
func (s *Service) Accounts(ctx context.Context, userID, mailboxID int64) ([]mail.Account, error) {
	var rows []pgstore.Mailbox
	if mailboxID > 0 {
		row, err := s.store.Mailbox(ctx, userID, mailboxID)
		if err != nil {
			return nil, err
		}
		rows = []pgstore.Mailbox{row}
	} else {
		var err error
		if rows, err = s.store.Mailboxes(ctx, userID); err != nil {
			return nil, err
		}
	}
	out := make([]mail.Account, 0, len(rows))
	for _, r := range rows {
		acc, err := s.Account(r)
		if err != nil {
			return nil, err
		}
		out = append(out, acc)
	}
	return out, nil
}

func (s *Service) decrypt(row pgstore.Mailbox) (string, error) {
	b, err := s.cipher.Decrypt(row.PasswordEnc, aad(row.UserID, row.Username))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// aad привязывает шифротекст к владельцу и логину.
func aad(userID int64, username string) []byte {
	return []byte(fmt.Sprintf("email-mcp:mailbox:%d:%s", userID, strings.ToLower(username)))
}
