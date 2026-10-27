package mail

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	netmail "net/mail"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	gocharset "github.com/emersion/go-message/charset"
	gomail "github.com/emersion/go-message/mail"
)

// OutAttachment — вложение исходящего письма.
type OutAttachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// Outgoing — письмо к отправке или в черновик.
type Outgoing struct {
	From       string
	To         []string
	Cc         []string
	Bcc        []string
	ReplyTo    string
	Subject    string
	Text       string
	HTML       string
	InReplyTo  string
	References string
	Attach     []OutAttachment
}

// Пределы — те же, что в исходном mail-mcp.
const (
	MaxRecipientsPerField = 50
	MaxSubjectChars       = 998
	MaxAttachmentsBytes   = 25 << 20
)

var wordDecoder = &mime.WordDecoder{CharsetReader: charsetReader}

func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	return gocharset.Reader(charset, input)
}

// decodeHeader раскрывает =?utf-8?b?…?= в заголовке; ошибка — как есть.
func decodeHeader(v string) string {
	if v == "" {
		return ""
	}
	if d, err := wordDecoder.DecodeHeader(v); err == nil {
		return d
	}
	return v
}

func parseDate(v string) (time.Time, error) { return netmail.ParseDate(strings.TrimSpace(v)) }

// ParseAddress проверяет один адрес и возвращает его в каноническом виде.
func ParseAddress(s string) (*netmail.Address, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return nil, inputf("пустой или многострочный адрес")
	}
	a, err := netmail.ParseAddress(s)
	if err != nil {
		return nil, inputf("адрес %q не разобран: %v", s, err)
	}
	return a, nil
}

func parseList(field string, list []string) ([]*netmail.Address, error) {
	if len(list) > MaxRecipientsPerField {
		return nil, inputf("%s: больше %d адресов", field, MaxRecipientsPerField)
	}
	out := make([]*netmail.Address, 0, len(list))
	for _, s := range list {
		a, err := ParseAddress(s)
		if err != nil {
			return nil, inputf("%s: %v", field, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func toGo(list []*netmail.Address) []*gomail.Address {
	out := make([]*gomail.Address, len(list))
	for i, a := range list {
		out[i] = (*gomail.Address)(a)
	}
	return out
}

// Built — собранное письмо.
type Built struct {
	Raw        []byte
	MessageID  string   // <…@домен отправителя>
	Recipients []string // To + Cc + Bcc, для конверта SMTP
}

// Build собирает RFC 822. keepBcc — оставить заголовок Bcc (черновик:
// иначе при отправке черновика скрытые получатели потерялись бы).
func (o *Outgoing) Build(keepBcc bool) (*Built, error) {
	from, err := ParseAddress(o.From)
	if err != nil {
		return nil, inputf("адрес отправителя: %v", err)
	}
	to, err := parseList("to", o.To)
	if err != nil {
		return nil, err
	}
	cc, err := parseList("cc", o.Cc)
	if err != nil {
		return nil, err
	}
	bcc, err := parseList("bcc", o.Bcc)
	if err != nil {
		return nil, err
	}
	if len(to)+len(cc)+len(bcc) == 0 {
		return nil, inputf("нет ни одного получателя")
	}
	subject := strings.TrimSpace(o.Subject)
	if subject == "" {
		return nil, inputf("пустая тема")
	}
	if utf8.RuneCountInString(subject) > MaxSubjectChars || strings.ContainsAny(subject, "\r\n") {
		return nil, inputf("тема — одна строка до %d символов", MaxSubjectChars)
	}
	if o.Text == "" && o.HTML == "" {
		return nil, inputf("нужен body_text или body_html")
	}
	total := 0
	for _, a := range o.Attach {
		total += len(a.Data)
	}
	if total > MaxAttachmentsBytes {
		return nil, inputf("вложения вместе больше %d МБ — большинство серверов такое письмо не примут", MaxAttachmentsBytes>>20)
	}

	var h gomail.Header
	h.SetDate(time.Now())
	h.SetAddressList("From", []*gomail.Address{(*gomail.Address)(from)})
	if len(to) > 0 {
		h.SetAddressList("To", toGo(to))
	}
	if len(cc) > 0 {
		h.SetAddressList("Cc", toGo(cc))
	}
	if keepBcc && len(bcc) > 0 {
		h.SetAddressList("Bcc", toGo(bcc))
	}
	if o.ReplyTo != "" {
		rt, err := ParseAddress(o.ReplyTo)
		if err != nil {
			return nil, inputf("reply_to: %v", err)
		}
		h.SetAddressList("Reply-To", []*gomail.Address{(*gomail.Address)(rt)})
	}
	h.SetSubject(subject)

	// Message-ID на домене отправителя: без своего идентификатора
	// ответ на письмо не встанет в цепочку, а часть серверов ставит
	// такое письмо в спам.
	msgID := newMessageID(from.Address)
	h.Set("Message-Id", msgID)
	if v := cleanIDs(o.InReplyTo); v != "" {
		h.Set("In-Reply-To", v)
	}
	if v := cleanIDs(o.References); v != "" {
		h.Set("References", v)
	}

	var buf bytes.Buffer
	if err := writeBody(&buf, h, o); err != nil {
		return nil, fmt.Errorf("сборка письма: %w", err)
	}

	rcpts := make([]string, 0, len(to)+len(cc)+len(bcc))
	seen := map[string]bool{}
	for _, l := range [][]*netmail.Address{to, cc, bcc} {
		for _, a := range l {
			k := strings.ToLower(a.Address)
			if !seen[k] {
				seen[k] = true
				rcpts = append(rcpts, a.Address)
			}
		}
	}
	return &Built{Raw: buf.Bytes(), MessageID: msgID, Recipients: rcpts}, nil
}

func writeBody(w io.Writer, h gomail.Header, o *Outgoing) error {
	if len(o.Attach) == 0 && (o.Text == "" || o.HTML == "") {
		var ih gomail.InlineHeader
		if o.HTML != "" {
			ih.SetContentType("text/html", map[string]string{"charset": "utf-8"})
		} else {
			ih.SetContentType("text/plain", map[string]string{"charset": "utf-8"})
		}
		for f := ih.Fields(); f.Next(); {
			h.Set(f.Key(), f.Value())
		}
		bw, err := gomail.CreateSingleInlineWriter(w, h)
		if err != nil {
			return err
		}
		body := o.Text
		if o.HTML != "" {
			body = o.HTML
		}
		if _, err := io.WriteString(bw, body); err != nil {
			return err
		}
		return bw.Close()
	}

	mw, err := gomail.CreateWriter(w, h)
	if err != nil {
		return err
	}
	iw, err := mw.CreateInline()
	if err != nil {
		return err
	}
	for _, part := range []struct{ ct, body string }{{"text/plain", o.Text}, {"text/html", o.HTML}} {
		if part.body == "" {
			continue
		}
		var ph gomail.InlineHeader
		ph.SetContentType(part.ct, map[string]string{"charset": "utf-8"})
		pw, err := iw.CreatePart(ph)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(pw, part.body); err != nil {
			return err
		}
		if err := pw.Close(); err != nil {
			return err
		}
	}
	if err := iw.Close(); err != nil {
		return err
	}
	for _, a := range o.Attach {
		var ah gomail.AttachmentHeader
		ct := a.ContentType
		if ct == "" {
			ct = mime.TypeByExtension(strings.ToLower(filepath.Ext(a.Filename)))
		}
		if ct == "" {
			ct = "application/octet-stream"
		}
		ah.SetContentType(ct, nil)
		ah.SetFilename(a.Filename)
		aw, err := mw.CreateAttachment(ah)
		if err != nil {
			return err
		}
		if _, err := aw.Write(a.Data); err != nil {
			return err
		}
		if err := aw.Close(); err != nil {
			return err
		}
	}
	return mw.Close()
}

func newMessageID(from string) string {
	domain := "localhost"
	if i := strings.LastIndexByte(from, '@'); i >= 0 && i < len(from)-1 {
		domain = from[i+1:]
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), hex.EncodeToString(b), domain)
}

// cleanIDs приводит список Message-ID к виду «<a> <b>»: модель
// присылает их то со скобками, то без, то через запятую.
func cleanIDs(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == ',' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.Trim(f, "<>")
		if f != "" && !strings.ContainsAny(f, "\r\n") {
			out = append(out, "<"+f+">")
		}
	}
	return strings.Join(out, " ")
}

// SafeFilename — имя вложения без путей: имя из письма — чужой ввод.
func SafeFilename(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '/' {
			return '_'
		}
		return r
	}, name)
	if name == "." || name == ".." || name == "" || name == "/" {
		return "attachment"
	}
	return name
}

// ParseAddressList разбирает заголовок со списком адресов.
func ParseAddressList(s string) ([]*netmail.Address, error) {
	return (&netmail.AddressParser{WordDecoder: wordDecoder}).ParseList(s)
}
