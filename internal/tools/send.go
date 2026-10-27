package tools

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MainAlexStark/email-mcp/mail"
)

// Правило предпросмотра повторено в описании каждого отправляющего
// инструмента и поля тела: шлюзы MCP нередко не пересылают модели
// инструкции сервера, а описание инструмента доезжает всегда.
const previewRule = " Перед вызовом покажите человеку полный предпросмотр (кому, копия, скрытая копия, тема, " +
	"текст, вложения) и получите явное согласие: отправленное письмо не вернуть."

const bodyRule = " body_text и body_html — разные поля: обычный текст кладите в body_text, HTML — только в body_html."

func attachmentsField(allowPath bool) obj {
	props := obj{
		"filename":       str("Имя файла, например отчёт.pdf."),
		"content_type":   str("MIME-тип; по умолчанию — по расширению."),
		"content_base64": str("Содержимое в base64."),
	}
	desc := "Вложения: filename + content_base64."
	if allowPath {
		props["file_path"] = str("Путь к файлу внутри разрешённой папки (MAIL_ATTACHMENT_UPLOAD_DIR).")
		desc = "Вложения: filename + content_base64 или file_path внутри разрешённой папки."
	}
	return arr(obj{"type": "object", "properties": props}, desc)
}

func addressList(desc string) obj {
	return arr(str(""), desc+` Адрес или "Имя <адрес>", до 50.`)
}

func composeFields(r *Registry) obj {
	return obj{
		"account_id":              accountField(),
		"to":                      addressList("Получатели."),
		"cc":                      addressList("Копия."),
		"bcc":                     addressList("Скрытая копия — другие получатели её не увидят."),
		"subject":                 str("Тема, одна строка."),
		"body_text":               str("Текст письма." + bodyRule),
		"body_html":               str("HTML-версия письма, если нужна." + bodyRule),
		"reply_to":                str("Адрес для ответов, если не совпадает с отправителем."),
		"in_reply_to":             str("Message-ID письма, на которое это ответ (для цепочки)."),
		"references":              str("Message-ID предыдущих писем цепочки через пробел."),
		"attachments":             attachmentsField(r.cfg.UploadDir != ""),
		"confirm_many_recipients": boolean("true, если человек подтвердил отправку на число адресов больше порога сервера."),
	}
}

// attachments разбирает вложения.
func (r *Registry) attachments(a Args) ([]mail.OutAttachment, error) {
	list, err := a.Objects("attachments")
	if err != nil {
		return nil, err
	}
	out := make([]mail.OutAttachment, 0, len(list))
	for i, item := range list {
		att := mail.OutAttachment{Filename: mail.SafeFilename(item.Str("filename")), ContentType: item.Str("content_type")}
		switch {
		case item.Str("content_base64") != "":
			data, err := base64.StdEncoding.DecodeString(item.Str("content_base64"))
			if err != nil {
				return nil, inputf("attachments[%d].content_base64 не разобран: %v", i, err)
			}
			att.Data = data
		case item.Str("file_path") != "":
			data, name, err := r.readUpload(item.Str("file_path"))
			if err != nil {
				return nil, err
			}
			att.Data = data
			if item.Str("filename") == "" {
				att.Filename = name
			}
		default:
			return nil, inputf("attachments[%d]: нужен content_base64", i)
		}
		if item.Str("filename") == "" && att.Filename == "attachment" {
			return nil, inputf("attachments[%d]: укажите filename", i)
		}
		out = append(out, att)
	}
	return out, nil
}

// readUpload читает файл для вложения, только если он внутри
// разрешённой папки.
//
// Путь приводится к настоящему (.. и симлинки раскрыты) до проверки.
// Отсутствующий и запрещённый файл дают одну и ту же ошибку: иначе
// инструмент превращался бы в способ узнать, какие файлы есть на диске.
func (r *Registry) readUpload(p string) ([]byte, string, error) {
	denied := inputf("file_path недоступен: вложения с диска разрешены только из папки, заданной " +
		"MAIL_ATTACHMENT_UPLOAD_DIR. Передайте содержимое в content_base64")
	if r.cfg.UploadDir == "" {
		return nil, "", denied
	}
	root, err := filepath.EvalSymlinks(r.cfg.UploadDir)
	if err != nil {
		return nil, "", denied
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return nil, "", denied
	}
	rel, err := filepath.Rel(root, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, "", denied
	}
	st, err := os.Stat(real)
	if err != nil || st.IsDir() {
		return nil, "", denied
	}
	if st.Size() > mail.MaxAttachmentsBytes {
		return nil, "", inputf("файл %s больше %d МБ", filepath.Base(real), mail.MaxAttachmentsBytes>>20)
	}
	data, err := os.ReadFile(real)
	if err != nil {
		return nil, "", denied
	}
	return data, filepath.Base(real), nil
}

// outgoing собирает письмо из аргументов.
func (r *Registry) outgoing(a Args) (mail.Outgoing, error) {
	var o mail.Outgoing
	var err error
	if o.To, err = a.Strings("to"); err != nil {
		return o, err
	}
	if o.Cc, err = a.Strings("cc"); err != nil {
		return o, err
	}
	if o.Bcc, err = a.Strings("bcc"); err != nil {
		return o, err
	}
	o.Subject = a.Str("subject")
	o.Text = a.Raw("body_text")
	o.HTML = a.Raw("body_html")
	o.ReplyTo = a.Str("reply_to")
	o.InReplyTo = a.Str("in_reply_to")
	o.References = a.Str("references")
	if o.Attach, err = r.attachments(a); err != nil {
		return o, err
	}
	if looksLikeHTML(o.Text) && o.HTML == "" {
		// Модель регулярно кладёт HTML в текстовое поле, и получатель
		// видит голые теги. Отказ с объяснением дешевле такого письма.
		return o, inputf("body_text похож на HTML. Положите HTML в body_html, а в body_text — обычный текст (или ничего)")
	}
	return o, nil
}

func looksLikeHTML(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "<html") || strings.Contains(l, "<body") ||
		(strings.Contains(l, "<p>") && strings.Contains(l, "</p>")) || strings.Contains(l, "<br>") || strings.Contains(l, "<div")
}

func recipients(o mail.Outgoing) int { return len(o.To) + len(o.Cc) + len(o.Bcc) }

// RegisterSend — отправка писем.
func (r *Registry) RegisterSend() {
	r.Add(Spec{
		Name:   "smtp_send_message",
		Desc:   "Отправить новое письмо с ящика и сохранить копию в «Отправленные»." + previewRule,
		Access: AccessSend,
		Schema: schema(composeFields(r), "to", "subject"),
		Do: func(ctx context.Context, a Args) (any, error) {
			c, err := r.client(ctx, a)
			if err != nil {
				return nil, err
			}
			o, err := r.outgoing(a)
			if err != nil {
				return nil, err
			}
			if err := r.safetyFor(ctx).CheckRecipients(recipients(o), a.Bool("confirm_many_recipients")); err != nil {
				return nil, err
			}
			res, err := c.Send(ctx, o)
			if err != nil {
				return nil, err
			}
			return sendOut(c, res), nil
		},
	})

	r.Add(Spec{
		Name: "smtp_reply_message",
		Desc: "Ответить на письмо: тема Re:, цепочка (In-Reply-To/References), цитата исходного текста, " +
			"исходное помечается отвеченным. reply_all — ответить всем, кроме себя." + previewRule,
		Access: AccessSend,
		Schema: schema(obj{
			"account_id":                   accountField(),
			"message_id":                   messageIDField(),
			"body_text":                    str("Текст ответа (цитата добавится сама)." + bodyRule),
			"body_html":                    str("HTML-версия ответа." + bodyRule),
			"reply_all":                    boolean("Ответить всем получателям исходного письма."),
			"include_original_attachments": boolean("Приложить вложения исходного письма."),
			"attachments":                  attachmentsField(r.cfg.UploadDir != ""),
			"confirm_many_recipients":      boolean("true, если человек подтвердил ответ на число адресов больше порога."),
		}, "message_id"),
		Do: func(ctx context.Context, a Args) (any, error) {
			id, err := a.messageID("message_id")
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, id.Account)
			if err != nil {
				return nil, err
			}
			att, err := r.attachments(a)
			if err != nil {
				return nil, err
			}
			opt := mail.ReplyOptions{Text: a.Raw("body_text"), HTML: a.Raw("body_html"), ReplyAll: a.Bool("reply_all"),
				IncludeOriginalAttachments: a.Bool("include_original_attachments"), Attach: att}
			if looksLikeHTML(opt.Text) && opt.HTML == "" {
				return nil, inputf("body_text похож на HTML — положите его в body_html")
			}
			// Число адресов ответа всем известно только после чтения
			// исходного письма — собираем, проверяем, отправляем.
			if opt.ReplyAll {
				o, err := c.BuildReply(ctx, id, opt)
				if err != nil {
					return nil, err
				}
				if err := r.safetyFor(ctx).CheckRecipients(recipients(*o), a.Bool("confirm_many_recipients")); err != nil {
					return nil, err
				}
			}
			res, err := c.Reply(ctx, id, opt)
			if err != nil {
				return nil, err
			}
			return sendOut(c, res), nil
		},
	})

	r.Add(Spec{
		Name:   "smtp_forward_message",
		Desc:   "Переслать письмо с его вложениями: тема Fwd:, блок с исходными заголовками и текстом." + previewRule,
		Access: AccessSend,
		Schema: schema(obj{
			"account_id":              accountField(),
			"message_id":              messageIDField(),
			"to":                      addressList("Кому переслать."),
			"cc":                      addressList("Копия."),
			"body_text":               str("Сопроводительный текст перед пересылаемым письмом." + bodyRule),
			"body_html":               str("HTML-версия сопроводительного текста." + bodyRule),
			"confirm_many_recipients": boolean("true, если человек подтвердил пересылку на число адресов больше порога."),
		}, "message_id", "to"),
		Do: func(ctx context.Context, a Args) (any, error) {
			id, err := a.messageID("message_id")
			if err != nil {
				return nil, err
			}
			c, err := r.clientByID(ctx, id.Account)
			if err != nil {
				return nil, err
			}
			to, err := a.Strings("to")
			if err != nil {
				return nil, err
			}
			cc, err := a.Strings("cc")
			if err != nil {
				return nil, err
			}
			if err := r.safetyFor(ctx).CheckRecipients(len(to)+len(cc), a.Bool("confirm_many_recipients")); err != nil {
				return nil, err
			}
			res, err := c.Forward(ctx, id, mail.ForwardOptions{To: to, Cc: cc, Text: a.Raw("body_text"), HTML: a.Raw("body_html")})
			if err != nil {
				return nil, err
			}
			return sendOut(c, res), nil
		},
	})
}

func sendOut(c *mail.Client, res mail.SendResult) obj {
	status := "ok"
	if len(res.Issues) > 0 {
		status = "partial"
	}
	return obj{
		"status":     status,
		"account_id": c.Account().ID,
		"summary":    fmt.Sprintf("Письмо отправлено: %d получателей", len(res.Recipients)),
		"result":     res,
	}
}
