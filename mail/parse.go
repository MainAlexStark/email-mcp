package mail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"unicode/utf8"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // koi8-r, windows-1251 и прочие: без них русские письма приходят кракозябрами
	gomail "github.com/emersion/go-message/mail"
	"github.com/microcosm-cc/bluemonday"
	"golang.org/x/net/html"
)

// Part — лист MIME-дерева.
type Part struct {
	PartID      string
	ContentType string
	Filename    string
	Disposition string
	ContentID   string
	Data        []byte
}

// IsAttachment — часть показывается как вложение, а не как текст письма.
func (p *Part) IsAttachment() bool {
	if p.Disposition == "attachment" {
		return true
	}
	if p.Filename != "" {
		return true
	}
	return !strings.HasPrefix(p.ContentType, "text/") && !strings.HasPrefix(p.ContentType, "multipart/")
}

// Parsed — разобранное письмо.
type Parsed struct {
	Header  message.Header
	Text    string
	HTML    string
	Parts   []*Part
	Subject string
}

// maxParseBytes — больше письмо целиком не разбираем. Письма в десятки
// мегабайт почти всегда — это вложения, и для них есть imap_get_attachment.
const maxParseBytes = 50 << 20

// Parse разбирает RFC 822. Сломанная часть не роняет всё письмо:
// почтовые программы пишут MIME очень по-разному, и половина письма
// лучше, чем ничего.
func Parse(raw []byte) (*Parsed, error) {
	if len(raw) > maxParseBytes {
		raw = raw[:maxParseBytes]
	}
	ent, err := message.Read(bytes.NewReader(raw))
	if ent == nil {
		return nil, fmt.Errorf("письмо не разобрано: %w", err)
	}
	p := &Parsed{Header: ent.Header}
	h := gomail.Header{Header: ent.Header}
	p.Subject, _ = h.Subject()
	if p.Subject == "" {
		p.Subject = ent.Header.Get("Subject")
	}
	walk(ent, "", p)
	for _, part := range p.Parts {
		if part.IsAttachment() {
			continue
		}
		switch {
		case part.ContentType == "text/plain" && p.Text == "":
			p.Text = string(part.Data)
		case part.ContentType == "text/html" && p.HTML == "":
			p.HTML = string(part.Data)
		}
	}
	return p, nil
}

// walk обходит дерево, присваивая части номера как в IMAP BODYSTRUCTURE
// (1, 2.1, 2.2): по этим номерам модель потом просит вложение.
func walk(e *message.Entity, id string, p *Parsed) {
	if mr := e.MultipartReader(); mr != nil {
		for n := 1; ; n++ {
			child, err := mr.NextPart()
			if child == nil || errors.Is(err, io.EOF) {
				return
			}
			cid := fmt.Sprint(n)
			if id != "" {
				cid = id + "." + cid
			}
			walk(child, cid, p)
			if err != nil {
				return
			}
		}
	}
	if id == "" {
		id = "1"
	}
	ct, params, _ := e.Header.ContentType()
	if ct == "" {
		ct = "text/plain"
	}
	disp, dparams, _ := e.Header.ContentDisposition()
	name := dparams["filename"]
	if name == "" {
		name = params["name"]
	}
	if name != "" {
		if dec, err := new(mime.WordDecoder).DecodeHeader(name); err == nil {
			name = dec
		}
	}
	data, _ := io.ReadAll(io.LimitReader(e.Body, maxParseBytes))
	if strings.HasPrefix(ct, "text/") && !utf8.Valid(data) {
		data = bytes.ToValidUTF8(data, []byte("�"))
	}
	p.Parts = append(p.Parts, &Part{
		PartID:      id,
		ContentType: strings.ToLower(ct),
		Filename:    name,
		Disposition: strings.ToLower(disp),
		ContentID:   strings.Trim(e.Header.Get("Content-Id"), "<>"),
		Data:        data,
	})
}

// Attachments — части-вложения.
func (p *Parsed) Attachments() []*Part {
	var out []*Part
	for _, part := range p.Parts {
		if part.IsAttachment() {
			out = append(out, part)
		}
	}
	return out
}

// FindPart ищет вложение по номеру или имени файла (без регистра).
func (p *Parsed) FindPart(partID, filename string) (*Part, error) {
	for _, part := range p.Parts {
		if partID != "" && part.PartID == partID {
			return part, nil
		}
	}
	if partID == "" && filename != "" {
		for _, part := range p.Parts {
			if strings.EqualFold(part.Filename, filename) {
				return part, nil
			}
		}
	}
	var names []string
	for _, a := range p.Attachments() {
		names = append(names, fmt.Sprintf("%s (%s)", a.PartID, a.Filename))
	}
	return nil, notFoundf("вложение не найдено; в письме есть: %s", strings.Join(names, ", "))
}

// BodyText — текст письма; если есть только HTML, текст из него.
func (p *Parsed) BodyText() string {
	if strings.TrimSpace(p.Text) != "" {
		return p.Text
	}
	if p.HTML != "" {
		return HTMLToText(p.HTML)
	}
	return ""
}

var sanitizer = bluemonday.UGCPolicy()

// SanitizeHTML вычищает скрипты, обработчики событий и внешние формы:
// HTML из письма — чужой ввод, и показывать его модели или человеку
// как есть нельзя.
func SanitizeHTML(s string) string { return sanitizer.Sanitize(s) }

// HTMLToText — грубый, но надёжный текст из HTML: блоки — переводы
// строк, скрипты и стили выкинуты.
func HTMLToText(s string) string {
	z := html.NewTokenizer(strings.NewReader(s))
	var b strings.Builder
	skip := 0
	for {
		switch z.Next() {
		case html.ErrorToken:
			return collapseBlank(b.String())
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "script", "style", "head", "title":
				skip++
			case "br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "table", "blockquote":
				b.WriteByte('\n')
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "script", "style", "head", "title":
				if skip > 0 {
					skip--
				}
			case "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "table":
				b.WriteByte('\n')
			}
		case html.TextToken:
			if skip == 0 {
				b.Write(z.Text())
			}
		}
	}
}

func collapseBlank(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	blank := 0
	for _, l := range lines {
		l = strings.TrimRight(strings.Join(strings.Fields(l), " "), " ")
		if l == "" {
			blank++
			if blank > 1 {
				continue
			}
		} else {
			blank = 0
		}
		out = append(out, l)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// Truncate обрезает по символам, не разрезая UTF-8.
func Truncate(s string, max int) (string, bool) {
	if max <= 0 || utf8.RuneCountInString(s) <= max {
		return s, false
	}
	n := 0
	for i := range s {
		if n == max {
			return s[:i], true
		}
		n++
	}
	return s, false
}

// Snippet — короткий фрагмент текста письма для списка. raw может
// быть началом письма: обрыв посреди MIME не страшен.
func Snippet(raw []byte, max int) string {
	if max <= 0 {
		max = 200
	}
	p, err := Parse(raw)
	if err != nil {
		return ""
	}
	t := strings.Join(strings.Fields(p.BodyText()), " ")
	t, cut := Truncate(t, max)
	if cut {
		t += "…"
	}
	return t
}
