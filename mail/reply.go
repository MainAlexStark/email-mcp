package mail

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	gomail "github.com/emersion/go-message/mail"
)

// ReplyOptions — ответ на письмо.
type ReplyOptions struct {
	Text                       string
	HTML                       string
	ReplyAll                   bool
	IncludeOriginalAttachments bool
	Attach                     []OutAttachment
}

// original — то, что нужно от исходного письма для ответа и пересылки.
type original struct {
	parsed     *Parsed
	from       []*gomail.Address
	replyTo    []*gomail.Address
	to, cc     []*gomail.Address
	messageID  string
	references string
	date       string
}

func (c *Client) loadOriginal(ctx context.Context, id MessageID) (*original, error) {
	raw, _, err := c.FetchRaw(ctx, id)
	if err != nil {
		return nil, err
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, &Error{Kind: KindServer, Msg: err.Error()}
	}
	h := gomail.Header{Header: p.Header}
	o := &original{parsed: p}
	o.from, _ = h.AddressList("From")
	o.replyTo, _ = h.AddressList("Reply-To")
	o.to, _ = h.AddressList("To")
	o.cc, _ = h.AddressList("Cc")
	o.messageID = strings.TrimSpace(p.Header.Get("Message-Id"))
	o.references = strings.TrimSpace(p.Header.Get("References"))
	o.date = p.Header.Get("Date")
	return o, nil
}

func addrStrings(list []*gomail.Address, skip map[string]bool) []string {
	var out []string
	for _, a := range list {
		k := strings.ToLower(a.Address)
		if skip[k] {
			continue
		}
		skip[k] = true
		out = append(out, a.String())
	}
	return out
}

func prefixed(subject, prefix string) string {
	s := strings.TrimSpace(subject)
	if s == "" {
		s = "(без темы)"
	}
	// «Re: Re: Re:» растёт с каждым ответом и в длинной переписке
	// съедает тему целиком.
	aliases := map[string][]string{"Re:": {"re:", "отв:"}, "Fwd:": {"fwd:", "fw:", "пересл:"}}
	low := strings.ToLower(s)
	for _, p := range aliases[prefix] {
		if strings.HasPrefix(low, p) {
			return s
		}
	}
	return prefix + " " + s
}

func quoteText(text, who, when string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n\n%s, %s пишет:\n", when, who)
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		b.WriteString("> ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// BuildReply собирает ответ, не отправляя: черновик ответа делается
// тем же кодом, что и отправка.
func (c *Client) BuildReply(ctx context.Context, id MessageID, opt ReplyOptions) (*Outgoing, error) {
	if strings.TrimSpace(opt.Text) == "" && strings.TrimSpace(opt.HTML) == "" {
		return nil, inputf("нужен body_text или body_html ответа")
	}
	o, err := c.loadOriginal(ctx, id)
	if err != nil {
		return nil, err
	}
	self := map[string]bool{strings.ToLower(c.acc.Sender()): true}
	target := o.replyTo
	if len(target) == 0 {
		target = o.from
	}
	to := addrStrings(target, self)
	var cc []string
	if opt.ReplyAll {
		to = append(to, addrStrings(o.to, self)...)
		cc = addrStrings(o.cc, self)
	}
	if len(to) == 0 && len(cc) == 0 {
		return nil, inputf("отвечать некому: письмо отправлено с этого же ящика. Используйте smtp_send_message")
	}
	who := "отправитель"
	if len(o.from) > 0 {
		who = o.from[0].String()
	}
	when := o.date
	if d, err := parseDate(o.date); err == nil {
		when = d.Format("02.01.2006 15:04")
	}

	out := &Outgoing{
		To: to, Cc: cc,
		Subject:    prefixed(o.parsed.Subject, "Re:"),
		InReplyTo:  o.messageID,
		References: strings.TrimSpace(o.references + " " + o.messageID),
		Attach:     opt.Attach,
	}
	orig := o.parsed.BodyText()
	if opt.Text != "" {
		out.Text = opt.Text + quoteText(orig, who, when)
	}
	if opt.HTML != "" {
		out.HTML = opt.HTML + "<br><br><div>" + html.EscapeString(when+", "+who) +
			" пишет:</div><blockquote style=\"margin:0 0 0 .8ex;border-left:1px solid #ccc;padding-left:1ex\">" +
			strings.ReplaceAll(html.EscapeString(orig), "\n", "<br>") + "</blockquote>"
	}
	if opt.IncludeOriginalAttachments {
		out.Attach = append(out.Attach, origAttachments(o.parsed)...)
	}
	return out, nil
}

func origAttachments(p *Parsed) []OutAttachment {
	var out []OutAttachment
	for _, a := range p.Attachments() {
		out = append(out, OutAttachment{Filename: SafeFilename(a.Filename), ContentType: a.ContentType, Data: a.Data})
	}
	return out
}

// Reply отвечает на письмо и помечает исходное как отвеченное.
func (c *Client) Reply(ctx context.Context, id MessageID, opt ReplyOptions) (SendResult, error) {
	out, err := c.BuildReply(ctx, id, opt)
	if err != nil {
		return SendResult{}, err
	}
	res, err := c.Send(ctx, *out)
	if err != nil {
		return res, err
	}
	// \Answered — не обязательная часть ответа: письмо уже ушло, и
	// отказ сервера поставить флаг не повод сообщать об ошибке.
	flagCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := c.imapSession(flagCtx, func(cl *imapclient.Client) error {
		if _, err := openMessage(cl, id, false); err != nil {
			return err
		}
		return cl.Store(imap.UIDSetNum(id.UID),
			&imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagAnswered}}, nil).Close()
	}); err != nil {
		res.Issues = append(res.Issues, "ответ отправлен, но исходное письмо не помечено отвеченным: "+err.Error())
	}
	return res, nil
}

// ForwardOptions — пересылка.
type ForwardOptions struct {
	To   []string
	Cc   []string
	Text string
	HTML string
}

// BuildForward собирает пересылку с вложениями исходного письма.
func (c *Client) BuildForward(ctx context.Context, id MessageID, opt ForwardOptions) (*Outgoing, error) {
	if len(opt.To) == 0 {
		return nil, inputf("укажите получателей пересылки в to")
	}
	o, err := c.loadOriginal(ctx, id)
	if err != nil {
		return nil, err
	}
	var hdr strings.Builder
	hdr.WriteString("\n\n---------- Пересылаемое сообщение ----------\n")
	if len(o.from) > 0 {
		fmt.Fprintf(&hdr, "От: %s\n", o.from[0].String())
	}
	if o.date != "" {
		fmt.Fprintf(&hdr, "Дата: %s\n", o.date)
	}
	fmt.Fprintf(&hdr, "Тема: %s\n", o.parsed.Subject)
	if len(o.to) > 0 {
		fmt.Fprintf(&hdr, "Кому: %s\n", strings.Join(addrStrings(o.to, map[string]bool{}), ", "))
	}
	hdr.WriteString("\n")
	body := o.parsed.BodyText()

	out := &Outgoing{
		To: opt.To, Cc: opt.Cc,
		Subject: prefixed(o.parsed.Subject, "Fwd:"),
		Text:    opt.Text + hdr.String() + body,
		Attach:  origAttachments(o.parsed),
	}
	if opt.HTML != "" {
		out.HTML = opt.HTML + "<br><br><pre>" + html.EscapeString(hdr.String()) + "</pre>" +
			strings.ReplaceAll(html.EscapeString(body), "\n", "<br>")
	}
	return out, nil
}

// Forward пересылает письмо.
func (c *Client) Forward(ctx context.Context, id MessageID, opt ForwardOptions) (SendResult, error) {
	out, err := c.BuildForward(ctx, id, opt)
	if err != nil {
		return SendResult{}, err
	}
	return c.Send(ctx, *out)
}
