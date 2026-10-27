package mail

import (
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// ErrNoSMTP — у ящика не настроена отправка.
func errNoSMTP(id string) error {
	return inputf("у ящика %q не настроен SMTP — отправлять с него нельзя. Добавьте SMTP-сервер в настройках ящика", id)
}

// smtpSession открывает SMTP-соединение с входом и выполняет fn.
func (c *Client) smtpSession(ctx context.Context, fn func(*smtp.Client) error) error {
	srv := c.acc.SMTP
	if !srv.Configured() {
		return errNoSMTP(c.acc.ID)
	}
	ctx, cancel := context.WithTimeout(ctx, c.acc.timeout())
	defer cancel()

	conn, err := c.dial(ctx, srv)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	var cl *smtp.Client
	if srv.Security == SecurityStartTLS {
		cl, err = smtp.NewClientStartTLS(conn, c.tlsConfig(srv.Host))
		if err != nil {
			conn.Close()
			return classify(ctxErr(ctx, err), srv.Host, stageConnect)
		}
	} else {
		cl = smtp.NewClient(conn)
	}
	defer cl.Close()
	cl.CommandTimeout = c.acc.timeout()
	cl.SubmissionTimeout = c.acc.timeout()

	if err := cl.Hello(heloName(c.acc.Sender())); err != nil {
		return classify(ctxErr(ctx, err), srv.Host, stageConnect)
	}
	// PLAIN поддерживают почти все; LOGIN — запасной для старых
	// Exchange и части хостингов, которые PLAIN не объявляют.
	user, pass := c.acc.Username, c.acc.Password
	if c.acc.SMTPUsername != "" {
		user, pass = c.acc.SMTPUsername, c.acc.SMTPPassword
	}
	var auth sasl.Client = sasl.NewPlainClient("", user, pass)
	if !cl.SupportsAuth(sasl.Plain) && cl.SupportsAuth(sasl.Login) {
		auth = sasl.NewLoginClient(user, pass)
	}
	if err := cl.Auth(auth); err != nil {
		return classify(ctxErr(ctx, err), srv.Host, stageLogin)
	}
	if err := fn(cl); err != nil {
		return classify(ctxErr(ctx, err), srv.Host, "отправка")
	}
	_ = cl.Quit()
	return nil
}

// heloName — имя для EHLO. «localhost» часть серверов считает
// признаком спамера; домен отправителя честнее.
func heloName(from string) string {
	if i := strings.LastIndexByte(from, '@'); i >= 0 && i < len(from)-1 {
		return from[i+1:]
	}
	return "localhost"
}

// VerifySMTP входит на SMTP-сервер, ничего не отправляя.
func (c *Client) VerifySMTP(ctx context.Context) (VerifyResult, error) {
	start := time.Now()
	res := VerifyResult{Host: c.acc.SMTP.Host, Port: c.acc.SMTP.Port, Security: c.acc.SMTP.Security}
	err := c.smtpSession(ctx, func(cl *smtp.Client) error {
		for _, ext := range []string{"SIZE", "8BITMIME", "SMTPUTF8", "PIPELINING", "DSN"} {
			if ok, _ := cl.Extension(ext); ok {
				res.Capabilities = append(res.Capabilities, ext)
			}
		}
		return nil
	})
	res.LatencyMS = time.Since(start).Milliseconds()
	res.OK = err == nil
	return res, err
}

// SendResult — итог отправки.
type SendResult struct {
	MessageID   string   `json:"message_id"`
	Recipients  []string `json:"recipients"`
	SavedToSent bool     `json:"saved_to_sent"`
	SentMailbox string   `json:"sent_mailbox,omitempty"`
	SentCopyID  string   `json:"sent_copy_message_id,omitempty"`
	Issues      []string `json:"issues,omitempty"`
}

// SendBuilt отправляет собранное письмо и кладёт копию в «Отправленные».
//
// Сбой после отправки (не удалось сохранить копию) — не ошибка вызова,
// а запись в Issues: письмо уже ушло, и ошибка спровоцировала бы модель
// отправить его второй раз.
func (c *Client) SendBuilt(ctx context.Context, b *Built) (SendResult, error) {
	from := c.acc.Sender()
	if from == "" {
		return SendResult{}, inputf("у ящика %q не задан адрес отправителя", c.acc.ID)
	}
	err := c.smtpSession(ctx, func(cl *smtp.Client) error {
		return cl.SendMail(from, b.Recipients, bytes.NewReader(b.Raw))
	})
	if err != nil {
		return SendResult{}, err
	}
	res := SendResult{MessageID: b.MessageID, Recipients: b.Recipients}
	if !c.acc.ShouldSaveSent() || !c.acc.IMAP.Configured() {
		return res, nil
	}
	// Копия в «Отправленные» — новым контекстом: если клиент MCP уже
	// отключился, письмо всё равно ушло, и история должна это помнить.
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	err = c.imapSession(saveCtx, func(cl *imapclient.Client) error {
		sent, err := findRole(cl, RoleSent)
		if err != nil {
			return err
		}
		if sent == "" {
			res.Issues = append(res.Issues, "письмо отправлено, но папка «Отправленные» не найдена — копия не сохранена")
			return nil
		}
		id, err := appendTo(cl, c.acc.ID, sent, b.Raw, []imap.Flag{imap.FlagSeen})
		if err != nil {
			return err
		}
		res.SavedToSent, res.SentMailbox, res.SentCopyID = true, sent, id
		return nil
	})
	if err != nil {
		res.Issues = append(res.Issues, "письмо отправлено, но копия в «Отправленные» не сохранена: "+err.Error())
	}
	return res, nil
}

// Send собирает и отправляет письмо от имени ящика.
func (c *Client) Send(ctx context.Context, o Outgoing) (SendResult, error) {
	o.From = c.fromHeader()
	b, err := o.Build(false)
	if err != nil {
		return SendResult{}, err
	}
	return c.SendBuilt(ctx, b)
}

// fromHeader — From с отображаемым именем.
func (c *Client) fromHeader() string {
	addr := c.acc.Sender()
	if c.acc.DisplayName != "" && addr != "" {
		return quoteName(c.acc.DisplayName) + " <" + addr + ">"
	}
	return addr
}

func quoteName(n string) string {
	n = strings.NewReplacer(`"`, `'`, "\r", "", "\n", "").Replace(n)
	return `"` + n + `"`
}
