package mail

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/ledongthuc/pdf"
)

// fetched — письмо как оно лежит на сервере.
type fetched struct {
	Mailbox     string
	UIDValidity uint32
	Raw         []byte
	Flags       []imap.Flag
	Internal    time.Time
}

// openMessage открывает папку письма и сверяет UIDVALIDITY.
func openMessage(cl *imapclient.Client, id MessageID, readOnly bool) (*imap.SelectData, error) {
	sel, err := cl.Select(id.Mailbox, &imap.SelectOptions{ReadOnly: readOnly}).Wait()
	if err != nil {
		return nil, err
	}
	if err := checkUIDValidity(id, sel.UIDValidity); err != nil {
		return nil, err
	}
	return sel, nil
}

func fetchRaw(cl *imapclient.Client, id MessageID) (*fetched, error) {
	sel, err := openMessage(cl, id, true)
	if err != nil {
		return nil, err
	}
	section := &imap.FetchItemBodySection{Peek: true}
	bufs, err := cl.Fetch(imap.UIDSetNum(id.UID), &imap.FetchOptions{
		UID: true, Flags: true, InternalDate: true, BodySection: []*imap.FetchItemBodySection{section},
	}).Collect()
	if err != nil {
		return nil, err
	}
	if len(bufs) == 0 {
		return nil, notFoundf("письма %s нет: его удалили или перенесли", id)
	}
	return &fetched{
		Mailbox:     id.Mailbox,
		UIDValidity: sel.UIDValidity,
		Raw:         bufs[0].FindBodySection(section),
		Flags:       bufs[0].Flags,
		Internal:    bufs[0].InternalDate,
	}, nil
}

// FetchRaw — исходник письма целиком.
func (c *Client) FetchRaw(ctx context.Context, id MessageID) ([]byte, []string, error) {
	var (
		raw   []byte
		flags []string
	)
	err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		f, err := fetchRaw(cl, id)
		if err != nil {
			return err
		}
		raw, flags = f.Raw, flagStrings(f.Flags)
		return nil
	})
	return raw, flags, err
}

// GetOptions — что включить в письмо.
type GetOptions struct {
	BodyMaxChars           int
	IncludeHeaders         bool
	IncludeAllHeaders      bool
	IncludeHTML            bool
	ExtractAttachmentText  bool
	AttachmentTextMaxChars int
}

// AttachmentInfo — вложение в ответе imap_get_message.
type AttachmentInfo struct {
	PartID        string `json:"part_id"`
	Filename      string `json:"filename,omitempty"`
	ContentType   string `json:"content_type"`
	SizeBytes     int    `json:"size_bytes"`
	Inline        bool   `json:"inline,omitempty"`
	ExtractedText string `json:"extracted_text,omitempty"`
	ExtractError  string `json:"extract_error,omitempty"`
}

// Header — пара заголовка.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Message — письмо целиком в виде для модели.
type Message struct {
	MessageID     string           `json:"message_id"`
	Mailbox       string           `json:"mailbox"`
	UIDValidity   uint32           `json:"uidvalidity"`
	UID           uint32           `json:"uid"`
	RFCMessageID  string           `json:"rfc_message_id,omitempty"`
	Date          string           `json:"date,omitempty"`
	From          string           `json:"from,omitempty"`
	To            string           `json:"to,omitempty"`
	Cc            string           `json:"cc,omitempty"`
	ReplyTo       string           `json:"reply_to,omitempty"`
	Subject       string           `json:"subject,omitempty"`
	Flags         []string         `json:"flags,omitempty"`
	Headers       []Header         `json:"headers,omitempty"`
	BodyText      string           `json:"body_text,omitempty"`
	BodyTruncated bool             `json:"body_truncated,omitempty"`
	BodyHTML      string           `json:"body_html,omitempty"`
	HTMLTruncated bool             `json:"body_html_truncated,omitempty"`
	Attachments   []AttachmentInfo `json:"attachments,omitempty"`
	SizeBytes     int              `json:"size_bytes"`
}

// curatedHeaders — то, что нужно модели для ответа и разбора
// переписки. Остальные (Received, DKIM, ARC) — килобайты шума.
var curatedHeaders = []string{
	"Date", "From", "Sender", "Reply-To", "To", "Cc", "Subject", "Message-Id",
	"In-Reply-To", "References", "List-Id", "List-Unsubscribe", "Auto-Submitted",
}

// MaxAttachmentExtract — больше этого текст из вложения не достаём.
const MaxAttachmentExtract = 5 << 20

// GetMessage читает и разбирает письмо.
func (c *Client) GetMessage(ctx context.Context, id MessageID, opt GetOptions) (*Message, error) {
	raw, flags, err := c.FetchRaw(ctx, id)
	if err != nil {
		return nil, err
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, &Error{Kind: KindServer, Msg: err.Error()}
	}
	h := p.Header
	m := &Message{
		MessageID:    id.String(),
		Mailbox:      id.Mailbox,
		UIDValidity:  id.UIDValidity,
		UID:          uint32(id.UID),
		RFCMessageID: strings.TrimSpace(h.Get("Message-Id")),
		From:         decodeHeader(h.Get("From")),
		To:           decodeHeader(h.Get("To")),
		Cc:           decodeHeader(h.Get("Cc")),
		ReplyTo:      decodeHeader(h.Get("Reply-To")),
		Subject:      p.Subject,
		Flags:        flags,
		SizeBytes:    len(raw),
	}
	if d, err := parseDate(h.Get("Date")); err == nil {
		m.Date = d.Format(time.RFC3339)
	}

	switch {
	case opt.IncludeAllHeaders:
		fields := h.Fields()
		for fields.Next() {
			m.Headers = append(m.Headers, Header{Name: fields.Key(), Value: decodeHeader(fields.Value())})
		}
	case opt.IncludeHeaders:
		for _, k := range curatedHeaders {
			if v := h.Get(k); v != "" {
				m.Headers = append(m.Headers, Header{Name: k, Value: decodeHeader(v)})
			}
		}
	}

	max := opt.BodyMaxChars
	if max <= 0 {
		max = 2000
	}
	m.BodyText, m.BodyTruncated = Truncate(p.BodyText(), max)
	if opt.IncludeHTML && p.HTML != "" {
		m.BodyHTML, m.HTMLTruncated = Truncate(SanitizeHTML(p.HTML), max)
	}

	for _, a := range p.Attachments() {
		info := AttachmentInfo{
			PartID: a.PartID, Filename: a.Filename, ContentType: a.ContentType,
			SizeBytes: len(a.Data), Inline: a.Disposition == "inline",
		}
		if opt.ExtractAttachmentText {
			text, err := ExtractText(a)
			if err != nil {
				info.ExtractError = err.Error()
			} else if text != "" {
				limit := opt.AttachmentTextMaxChars
				if limit <= 0 {
					limit = 10000
				}
				info.ExtractedText, _ = Truncate(text, limit)
			}
		}
		m.Attachments = append(m.Attachments, info)
		if len(m.Attachments) >= 50 {
			break
		}
	}
	return m, nil
}

// ExtractText достаёт текст из вложения: текстовые форматы и PDF.
// Пустая строка без ошибки — формат не поддерживается.
func ExtractText(p *Part) (text string, err error) {
	if len(p.Data) > MaxAttachmentExtract {
		return "", fmt.Errorf("вложение больше %d МБ — текст не извлекается", MaxAttachmentExtract>>20)
	}
	ct := p.ContentType
	name := strings.ToLower(p.Filename)
	switch {
	case strings.HasPrefix(ct, "text/") || ct == "application/json" || ct == "application/xml" ||
		strings.HasSuffix(name, ".csv") || strings.HasSuffix(name, ".txt"):
		return strings.ToValidUTF8(string(p.Data), "�"), nil
	case ct == "application/pdf" || strings.HasSuffix(name, ".pdf"):
		// Разбор PDF падает паникой на битых файлах, а битых PDF во
		// вложениях больше, чем кажется. Одно вложение не должно ронять
		// чтение письма.
		defer func() {
			if r := recover(); r != nil {
				text, err = "", fmt.Errorf("PDF не разобран")
			}
		}()
		r, err := pdf.NewReader(bytes.NewReader(p.Data), int64(len(p.Data)))
		if err != nil {
			return "", fmt.Errorf("PDF не разобран: %v", err)
		}
		tr, err := r.GetPlainText()
		if err != nil {
			return "", fmt.Errorf("PDF не разобран: %v", err)
		}
		var b bytes.Buffer
		if _, err := b.ReadFrom(tr); err != nil {
			return "", fmt.Errorf("PDF не разобран: %v", err)
		}
		return strings.TrimSpace(b.String()), nil
	}
	return "", nil
}

// GetAttachment — одно вложение письма.
func (c *Client) GetAttachment(ctx context.Context, id MessageID, partID, filename string) (*Part, error) {
	if partID == "" && filename == "" {
		return nil, inputf("укажите part_id или filename из imap_get_message")
	}
	raw, _, err := c.FetchRaw(ctx, id)
	if err != nil {
		return nil, err
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, &Error{Kind: KindServer, Msg: err.Error()}
	}
	return p.FindPart(partID, filename)
}
