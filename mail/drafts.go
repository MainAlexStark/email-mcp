package mail

import (
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	gomail "github.com/emersion/go-message/mail"
)

// Черновики лежат в папке Drafts самого ящика: человек видит их в своей
// почтовой программе, правит и отправляет оттуда же. Ради этого
// черновики и существуют — модель готовит письмо, решение за человеком.

func (c *Client) draftsMailbox(cl *imapclient.Client) (string, error) {
	name, err := findRole(cl, RoleDrafts)
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", notFoundf("в ящике %q нет папки черновиков (Drafts)", c.acc.ID)
	}
	return name, nil
}

// checkDraft — защита: всё, что делается с draft_id, делается только
// с письмами из папки черновиков. Иначе draft_delete был бы просто
// удалением любого письма под другим именем.
func (c *Client) checkDraft(cl *imapclient.Client, id MessageID) error {
	drafts, err := c.draftsMailbox(cl)
	if err != nil {
		return err
	}
	if id.Mailbox != drafts {
		return inputf("draft_id указывает на письмо в папке %q, а не в черновиках (%q): "+
			"черновые инструменты работают только с черновиками", id.Mailbox, drafts)
	}
	return nil
}

// DraftResult — итог создания или правки черновика.
type DraftResult struct {
	DraftID              string   `json:"draft_id"`
	Mailbox              string   `json:"mailbox"`
	MessageID            string   `json:"message_id"`
	PreviousDraftID      string   `json:"previous_draft_id,omitempty"`
	PreviousDraftRemoved bool     `json:"previous_draft_removed,omitempty"`
	Issues               []string `json:"issues,omitempty"`
}

// CreateDraft сохраняет письмо в черновики. Ничего не отправляется.
func (c *Client) CreateDraft(ctx context.Context, o Outgoing) (DraftResult, error) {
	o.From = c.fromHeader()
	b, err := o.Build(true)
	if err != nil {
		return DraftResult{}, err
	}
	var res DraftResult
	err = c.imapSession(ctx, func(cl *imapclient.Client) error {
		drafts, err := c.draftsMailbox(cl)
		if err != nil {
			return err
		}
		res.Mailbox, res.MessageID = drafts, b.MessageID
		id, err := appendTo(cl, c.acc.ID, drafts, b.Raw, []imap.Flag{imap.FlagDraft, imap.FlagSeen})
		if err != nil {
			return err
		}
		if id == "" {
			// Сервер без UIDPLUS не сообщает UID нового письма — ищем
			// его по Message-ID, который сами только что поставили.
			id, err = findByMessageID(cl, c.acc.ID, drafts, b.MessageID)
			if err != nil {
				return err
			}
			if id == "" {
				res.Issues = append(res.Issues, "черновик сохранён, но сервер не сообщил его номер — найдите его через draft_list")
			}
		}
		res.DraftID = id
		return nil
	})
	return res, err
}

func findByMessageID(cl *imapclient.Client, account, mailbox, msgID string) (string, error) {
	sel, err := cl.Select(mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return "", err
	}
	data, err := cl.UIDSearch(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: msgID}},
	}, nil).Wait()
	if err != nil {
		return "", err
	}
	uids := data.AllUIDs()
	if len(uids) == 0 {
		return "", nil
	}
	return MessageID{Account: account, Mailbox: mailbox, UIDValidity: sel.UIDValidity, UID: uids[len(uids)-1]}.String(), nil
}

// UpdateDraft заменяет черновик целиком.
//
// Сначала создаётся новая версия, потом удаляется старая: сбой между
// шагами оставит два черновика, но никогда — ни одного. Потерянный
// текст письма, над которым человек думал полчаса, хуже лишней копии.
func (c *Client) UpdateDraft(ctx context.Context, old MessageID, o Outgoing) (DraftResult, error) {
	if err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		if err := c.checkDraft(cl, old); err != nil {
			return err
		}
		_, err := openMessage(cl, old, true)
		return err
	}); err != nil {
		return DraftResult{}, err
	}
	res, err := c.CreateDraft(ctx, o)
	if err != nil {
		return res, err
	}
	res.PreviousDraftID = old.String()
	if _, err := c.removeDraft(ctx, old); err != nil {
		res.Issues = append(res.Issues, "новая версия сохранена, но старая не удалена: "+err.Error())
	} else {
		res.PreviousDraftRemoved = true
	}
	return res, nil
}

func (c *Client) removeDraft(ctx context.Context, id MessageID) (bool, error) {
	err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		if err := c.checkDraft(cl, id); err != nil {
			return err
		}
		if _, err := openMessage(cl, id, false); err != nil {
			return err
		}
		return expungeUIDs(cl, imap.UIDSetNum(id.UID))
	})
	return err == nil, err
}

// DeleteDraft удаляет черновик безвозвратно.
func (c *Client) DeleteDraft(ctx context.Context, id MessageID) error {
	_, err := c.removeDraft(ctx, id)
	return err
}

// DraftSummary — черновик в списке.
type DraftSummary struct {
	DraftID string `json:"draft_id"`
	Subject string `json:"subject,omitempty"`
	To      string `json:"to,omitempty"`
	Date    string `json:"date,omitempty"`
}

// ListDrafts — черновики, новые первыми.
func (c *Client) ListDrafts(ctx context.Context, limit int) ([]DraftSummary, error) {
	if limit <= 0 {
		limit = 20
	}
	var out []DraftSummary
	err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		drafts, err := c.draftsMailbox(cl)
		if err != nil {
			return err
		}
		sel, err := cl.Select(drafts, &imap.SelectOptions{ReadOnly: true}).Wait()
		if err != nil {
			return err
		}
		if sel.NumMessages == 0 {
			return nil
		}
		uids, err := searchUIDs(cl, Criteria{})
		if err != nil {
			return err
		}
		if len(uids) > limit {
			uids = uids[:limit]
		}
		list, err := fetchSummaries(cl, c.acc.ID, drafts, sel.UIDValidity, uids, false, 0)
		if err != nil {
			return err
		}
		for _, s := range list {
			out = append(out, DraftSummary{DraftID: s.MessageID, Subject: s.Subject, To: s.To, Date: s.Date})
		}
		return nil
	})
	if out == nil {
		out = []DraftSummary{}
	}
	return out, err
}

// DraftSendResult — итог отправки черновика.
type DraftSendResult struct {
	SendResult
	DraftID      string `json:"draft_id"`
	DraftRemoved bool   `json:"draft_removed"`
}

// SendDraft отправляет черновик и убирает его из черновиков.
func (c *Client) SendDraft(ctx context.Context, id MessageID) (DraftSendResult, error) {
	var raw []byte
	if err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		if err := c.checkDraft(cl, id); err != nil {
			return err
		}
		f, err := fetchRaw(cl, id)
		if err != nil {
			return err
		}
		raw = f.Raw
		return nil
	}); err != nil {
		return DraftSendResult{}, err
	}

	b, err := builtFromDraft(raw)
	if err != nil {
		return DraftSendResult{}, err
	}
	sent, err := c.SendBuilt(ctx, b)
	if err != nil {
		return DraftSendResult{}, err
	}
	res := DraftSendResult{SendResult: sent, DraftID: id.String()}
	rmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	if _, err := c.removeDraft(rmCtx, id); err != nil {
		res.Issues = append(res.Issues, "письмо отправлено, но черновик не удалён: "+err.Error())
	} else {
		res.DraftRemoved = true
	}
	return res, nil
}

// builtFromDraft готовит сохранённый черновик к отправке: получателей
// берёт из To/Cc/Bcc, Bcc вырезает (иначе скрытые получатели увидят
// друг друга), Date обновляет на текущую.
func builtFromDraft(raw []byte) (*Built, error) {
	p, err := Parse(raw)
	if err != nil {
		return nil, &Error{Kind: KindServer, Msg: err.Error()}
	}
	h := gomail.Header{Header: p.Header}
	var rcpts []string
	seen := map[string]bool{}
	for _, k := range []string{"To", "Cc", "Bcc"} {
		list, _ := h.AddressList(k)
		for _, a := range list {
			if l := strings.ToLower(a.Address); !seen[l] {
				seen[l] = true
				rcpts = append(rcpts, a.Address)
			}
		}
	}
	if len(rcpts) == 0 {
		return nil, inputf("в черновике нет получателей — добавьте их через draft_update")
	}
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	sep := "\r\n"
	if !ok {
		head, body, ok = bytes.Cut(raw, []byte("\n\n"))
		sep = "\n"
		if !ok {
			return nil, inputf("черновик повреждён: нет границы заголовков")
		}
	}
	lines := strings.Split(string(head), sep)
	var out []string
	drop := false
	for _, l := range lines {
		if l != "" && (l[0] == ' ' || l[0] == '\t') {
			if !drop {
				out = append(out, l)
			}
			continue
		}
		name, _, _ := strings.Cut(l, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		drop = name == "bcc" || name == "date"
		if !drop {
			out = append(out, l)
		}
	}
	out = append(out, "Date: "+time.Now().Format(time.RFC1123Z))
	var buf bytes.Buffer
	buf.WriteString(strings.Join(out, sep))
	buf.WriteString(sep + sep)
	buf.Write(body)
	return &Built{Raw: buf.Bytes(), MessageID: strings.TrimSpace(p.Header.Get("Message-Id")), Recipients: rcpts}, nil
}
