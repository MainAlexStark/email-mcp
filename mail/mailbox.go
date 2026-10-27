package mail

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// Mailbox — папка ящика.
type Mailbox struct {
	Name      string   `json:"name"`
	Delimiter string   `json:"delimiter,omitempty"`
	Role      string   `json:"role,omitempty"`
	Attrs     []string `json:"attributes,omitempty"`
	// NoSelect — папку нельзя открыть (только контейнер подпапок).
	NoSelect bool `json:"no_select,omitempty"`
}

// Роли папок. Имена совпадают с исходным mail-mcp: модель пишет
// «Sent», а мы находим «[Gmail]/Sent Mail» или «Отправленные».
const (
	RoleSent    = "sent"
	RoleDrafts  = "drafts"
	RoleTrash   = "trash"
	RoleJunk    = "junk"
	RoleArchive = "archive"
	RoleAll     = "all"
)

var roleAttrs = map[imap.MailboxAttr]string{
	imap.MailboxAttrSent:    RoleSent,
	imap.MailboxAttrDrafts:  RoleDrafts,
	imap.MailboxAttrTrash:   RoleTrash,
	imap.MailboxAttrJunk:    RoleJunk,
	imap.MailboxAttrArchive: RoleArchive,
	imap.MailboxAttrAll:     RoleAll,
}

// roleNames — запасной путь для серверов без SPECIAL-USE. Сравнение
// по последнему сегменту без регистра.
var roleNames = map[string]string{
	"sent": RoleSent, "sent items": RoleSent, "sent mail": RoleSent, "sent messages": RoleSent,
	"отправленные": RoleSent, "исходящие": RoleSent,
	"drafts": RoleDrafts, "draft": RoleDrafts, "черновики": RoleDrafts,
	"trash": RoleTrash, "deleted": RoleTrash, "deleted items": RoleTrash, "deleted messages": RoleTrash,
	"bin": RoleTrash, "корзина": RoleTrash, "удаленные": RoleTrash, "удалённые": RoleTrash,
	"junk": RoleJunk, "spam": RoleJunk, "junk e-mail": RoleJunk, "спам": RoleJunk,
	"archive": RoleArchive, "архив": RoleArchive,
	"all mail": RoleAll,
}

func roleOf(d *imap.ListData) string {
	for _, a := range d.Attrs {
		if r, ok := roleAttrs[a]; ok {
			return r
		}
	}
	name := d.Mailbox
	if d.Delim != 0 {
		if i := strings.LastIndex(name, string(d.Delim)); i >= 0 {
			name = name[i+1:]
		}
	}
	return roleNames[strings.ToLower(strings.TrimSpace(name))]
}

func listMailboxes(cl *imapclient.Client) ([]Mailbox, error) {
	data, err := cl.List("", "*", nil).Collect()
	if err != nil {
		return nil, err
	}
	out := make([]Mailbox, 0, len(data))
	for _, d := range data {
		mb := Mailbox{Name: d.Mailbox, Role: roleOf(d)}
		if d.Delim != 0 {
			mb.Delimiter = string(d.Delim)
		}
		for _, a := range d.Attrs {
			mb.Attrs = append(mb.Attrs, string(a))
			if a == imap.MailboxAttrNoSelect || a == imap.MailboxAttrNonExistent {
				mb.NoSelect = true
			}
		}
		out = append(out, mb)
	}
	// INBOX первым, остальные по алфавиту: модель читает список сверху
	// и на длинном списке до конца может не дойти.
	sort.SliceStable(out, func(i, j int) bool {
		ii, jj := strings.EqualFold(out[i].Name, "INBOX"), strings.EqualFold(out[j].Name, "INBOX")
		if ii != jj {
			return ii
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// ListMailboxes — все папки ящика.
func (c *Client) ListMailboxes(ctx context.Context) ([]Mailbox, error) {
	var out []Mailbox
	err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		var err error
		out, err = listMailboxes(cl)
		return err
	})
	return out, err
}

// resolveMailbox превращает «Sent», «Drafts», «Trash», «Junk» в
// настоящее имя папки у этого провайдера. Имя, которое уже существует,
// возвращается как есть: папка, которую человек сам назвал «Sent»,
// важнее догадки.
func resolveMailbox(cl *imapclient.Client, name string) (string, error) {
	role, isRole := roleNames[strings.ToLower(strings.TrimSpace(name))]
	if strings.EqualFold(name, "INBOX") || !isRole {
		return name, nil
	}
	list, err := listMailboxes(cl)
	if err != nil {
		return "", err
	}
	for _, mb := range list {
		if mb.Name == name {
			return name, nil
		}
	}
	for _, mb := range list {
		if mb.Role == role && !mb.NoSelect {
			return mb.Name, nil
		}
	}
	return name, nil
}

// findRole ищет папку роли; пустая строка — такой папки нет.
func findRole(cl *imapclient.Client, role string) (string, error) {
	list, err := listMailboxes(cl)
	if err != nil {
		return "", err
	}
	for _, mb := range list {
		if mb.Role == role && !mb.NoSelect {
			return mb.Name, nil
		}
	}
	return "", nil
}

// ValidMailboxName отсекает управляющие символы: они ломают протокол
// и бывают только следствием ошибки модели.
func ValidMailboxName(name string) error {
	if name == "" || len(name) > 256 {
		return inputf("имя папки должно быть от 1 до 256 символов")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return inputf("имя папки %q содержит управляющие символы", name)
		}
	}
	return nil
}

// MailboxStatus — счётчики папки.
type MailboxStatus struct {
	Mailbox     string `json:"mailbox"`
	Messages    uint32 `json:"messages"`
	Unseen      uint32 `json:"unseen"`
	UIDNext     uint32 `json:"uid_next,omitempty"`
	UIDValidity uint32 `json:"uidvalidity"`
}

// Status — сколько писем и непрочитанных, без открытия папки.
func (c *Client) Status(ctx context.Context, mailbox string) (MailboxStatus, error) {
	if err := ValidMailboxName(mailbox); err != nil {
		return MailboxStatus{}, err
	}
	var out MailboxStatus
	err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		name, err := resolveMailbox(cl, mailbox)
		if err != nil {
			return err
		}
		st, err := cl.Status(name, &imap.StatusOptions{
			NumMessages: true, NumUnseen: true, UIDNext: true, UIDValidity: true,
		}).Wait()
		if err != nil {
			return err
		}
		out = MailboxStatus{Mailbox: name, UIDNext: uint32(st.UIDNext), UIDValidity: st.UIDValidity}
		if st.NumMessages != nil {
			out.Messages = *st.NumMessages
		}
		if st.NumUnseen != nil {
			out.Unseen = *st.NumUnseen
		}
		return nil
	})
	return out, err
}

// CreateMailbox создаёт папку.
func (c *Client) CreateMailbox(ctx context.Context, name string) error {
	if err := ValidMailboxName(name); err != nil {
		return err
	}
	return c.imapSession(ctx, func(cl *imapclient.Client) error {
		return cl.Create(name, nil).Wait()
	})
}

// protectedMailbox — папки, удаление или переименование которых ломает
// ящик целиком: сервер их не даст, но по пути можно потерять письма.
func protectedMailbox(name string) bool {
	return strings.EqualFold(name, "INBOX")
}

// DeleteMailbox удаляет папку вместе с письмами.
func (c *Client) DeleteMailbox(ctx context.Context, name string) error {
	if err := ValidMailboxName(name); err != nil {
		return err
	}
	if protectedMailbox(name) {
		return inputf("INBOX удалить нельзя")
	}
	return c.imapSession(ctx, func(cl *imapclient.Client) error {
		list, err := listMailboxes(cl)
		if err != nil {
			return err
		}
		for _, mb := range list {
			if mb.Name == name {
				if mb.Role != "" {
					return inputf("папка %q — системная (%s): её удаление ломает почтовые программы", name, mb.Role)
				}
				return cl.Delete(name).Wait()
			}
		}
		return notFoundf("папки %q нет", name)
	})
}

// RenameMailbox переименовывает папку.
func (c *Client) RenameMailbox(ctx context.Context, from, to string) error {
	if err := ValidMailboxName(from); err != nil {
		return err
	}
	if err := ValidMailboxName(to); err != nil {
		return err
	}
	if protectedMailbox(from) {
		return inputf("INBOX переименовать нельзя")
	}
	return c.imapSession(ctx, func(cl *imapclient.Client) error {
		return cl.Rename(from, to, nil).Wait()
	})
}

// VerifyResult — итог проверки ящика.
type VerifyResult struct {
	OK           bool     `json:"ok"`
	LatencyMS    int64    `json:"latency_ms"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Security     Security `json:"security"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// VerifyIMAP входит в ящик и читает возможности сервера.
func (c *Client) VerifyIMAP(ctx context.Context) (VerifyResult, error) {
	start := time.Now()
	res := VerifyResult{Host: c.acc.IMAP.Host, Port: c.acc.IMAP.Port, Security: c.acc.IMAP.Security}
	err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		caps, err := cl.Capability().Wait()
		if err != nil {
			return err
		}
		for cp := range caps {
			res.Capabilities = append(res.Capabilities, string(cp))
		}
		sort.Strings(res.Capabilities)
		if len(res.Capabilities) > 256 {
			res.Capabilities = res.Capabilities[:256]
		}
		return nil
	})
	res.LatencyMS = time.Since(start).Milliseconds()
	res.OK = err == nil
	return res, err
}
