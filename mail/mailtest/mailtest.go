// Package mailtest — настоящие IMAP- и SMTP-серверы в памяти для тестов.
//
// Подставной клиент проверил бы только то, что мы правильно зовём свой
// же интерфейс. Ошибки живут в протоколе: в кодировке имени папки, в
// UID после MOVE, в границах MIME. Поэтому тесты ходят по сети к
// серверу, который говорит на IMAP и SMTP по-настоящему.
package mailtest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/MainAlexStark/email-mcp/mail"
)

const (
	User     = "alex@example.com"
	Password = "app-password"
)

// Server — пара IMAP + SMTP с одним пользователем.
type Server struct {
	IMAPAddr string
	SMTPAddr string
	User     *imapmemserver.User

	mu   sync.Mutex
	sent []Sent
	// logins считает подключения — тесты проверяют по нему, что запрос
	// до сервера не дошёл, когда защита сработала.
	logins int
}

// Sent — письмо, принятое SMTP-сервером.
type Sent struct {
	From string
	To   []string
	Data []byte
}

// Start поднимает серверы с папками INBOX, Sent, Drafts, Trash, Archive.
func Start(t testing.TB) *Server {
	t.Helper()
	s := &Server{}

	mem := imapmemserver.New()
	s.User = imapmemserver.NewUser(User, Password)
	for _, name := range []string{"INBOX", "Sent", "Drafts", "Trash", "Archive"} {
		if err := s.User.Create(name, nil); err != nil {
			t.Fatal(err)
		}
	}
	mem.AddUser(s.User)

	quiet := log.New(io.Discard, "", 0)
	imapSrv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}, imap.CapMove: {}, imap.CapNamespace: {},
		},
		InsecureAuth: true,
		Logger:       quiet,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go imapSrv.Serve(&countingListener{Listener: ln, srv: s})
	t.Cleanup(func() { imapSrv.Close() })
	s.IMAPAddr = ln.Addr().String()

	smtpSrv := smtp.NewServer(&smtpBackend{srv: s})
	smtpSrv.AllowInsecureAuth = true
	smtpSrv.Domain = "localhost"
	smtpSrv.ErrorLog = quiet
	sln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go smtpSrv.Serve(sln)
	t.Cleanup(func() { smtpSrv.Close() })
	s.SMTPAddr = sln.Addr().String()
	return s
}

// countingListener считает соединения. Обёртка сессии для этого не
// годится: сервер узнаёт поддержку MOVE и прочего по методам сессии,
// и обёртка их бы спрятала.
type countingListener struct {
	net.Listener
	srv *Server
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.srv.mu.Lock()
		l.srv.logins++
		l.srv.mu.Unlock()
	}
	return c, err
}

// Logins — сколько раз к IMAP подключались.
func (s *Server) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// SentMessages — что ушло через SMTP.
func (s *Server) SentMessages() []Sent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Sent(nil), s.sent...)
}

func hostPort(addr string) (string, int) {
	h, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return h, n
}

// Account — ящик, смотрящий на эти серверы.
func (s *Server) Account(id string) mail.Account {
	ih, ip := hostPort(s.IMAPAddr)
	sh, sp := hostPort(s.SMTPAddr)
	saveSent := true
	return mail.Account{
		ID:       id,
		Email:    User,
		IMAP:     mail.Server{Host: ih, Port: ip, Security: mail.SecurityNone},
		SMTP:     mail.Server{Host: sh, Port: sp, Security: mail.SecurityNone},
		Username: User,
		Password: Password,
		SaveSent: &saveSent,
		Timeout:  10 * time.Second,
	}
}

// Seed кладёт письмо в папку и возвращает его UID.
func (s *Server) Seed(t testing.TB, mailbox string, raw string, flags ...imap.Flag) imap.UID {
	t.Helper()
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\n", "\r\n")
	data, err := s.User.Append(mailbox, literal{bytes.NewReader([]byte(raw)), int64(len(raw))},
		&imap.AppendOptions{Flags: flags, Time: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return data.UID
}

// Message — простое текстовое письмо для Seed.
func Message(from, to, subject, body string) string {
	return fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\nDate: %s\nMessage-ID: <%d@example.com>\n"+
		"Content-Type: text/plain; charset=utf-8\n\n%s\n",
		from, to, subject, time.Now().Format(time.RFC1123Z), time.Now().UnixNano(), body)
}

type literal struct {
	*bytes.Reader
	n int64
}

func (l literal) Size() int64 { return l.n }

// --- SMTP ---

type smtpBackend struct{ srv *Server }

func (b *smtpBackend) NewSession(*smtp.Conn) (smtp.Session, error) {
	return &smtpSession{srv: b.srv}, nil
}

type smtpSession struct {
	srv    *Server
	authed bool
	from   string
	to     []string
}

func (s *smtpSession) AuthMechanisms() []string { return []string{sasl.Plain} }

func (s *smtpSession) Auth(string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, user, pass string) error {
		if user != User || pass != Password {
			return errors.New("invalid credentials")
		}
		s.authed = true
		return nil
	}), nil
}

func (s *smtpSession) Mail(from string, _ *smtp.MailOptions) error {
	if !s.authed {
		return &smtp.SMTPError{Code: 530, Message: "auth required"}
	}
	s.from = from
	return nil
}

func (s *smtpSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

func (s *smtpSession) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.srv.mu.Lock()
	s.srv.sent = append(s.srv.sent, Sent{From: s.from, To: append([]string(nil), s.to...), Data: b})
	s.srv.mu.Unlock()
	return nil
}

func (s *smtpSession) Reset()        { s.from, s.to = "", nil }
func (s *smtpSession) Logout() error { return nil }
