package mail

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// ValidFlags проверяет флаги: системные (\Seen) и ключевые слова
// (важное, $Label1). Пробелы и скобки ломают команду STORE.
func ValidFlags(flags []string) ([]imap.Flag, error) {
	out := make([]imap.Flag, 0, len(flags))
	for _, f := range flags {
		f = strings.TrimSpace(f)
		if f == "" || len(f) > 64 || strings.ContainsAny(f, " ()[]{}\"%*") {
			return nil, inputf("флаг %q недопустим: системные — \\Seen, \\Flagged, \\Answered, \\Draft; "+
				"свои — одно слово без пробелов и скобок", f)
		}
		for _, r := range f {
			if unicode.IsControl(r) {
				return nil, inputf("флаг %q содержит управляющие символы", f)
			}
		}
		// \seen и \Seen для сервера одно и то же, но в ответе модели
		// удобнее видеть каноническое написание.
		switch strings.ToLower(f) {
		case `\seen`:
			f = string(imap.FlagSeen)
		case `\flagged`:
			f = string(imap.FlagFlagged)
		case `\answered`:
			f = string(imap.FlagAnswered)
		case `\draft`:
			f = string(imap.FlagDraft)
		case `\deleted`:
			return nil, inputf(`флаг \Deleted ставится через imap_delete_message: так письмо не повиснет помеченным, но не удалённым`)
		}
		out = append(out, imap.Flag(f))
	}
	return out, nil
}

// UpdateFlags добавляет и снимает флаги, возвращает итоговые.
func (c *Client) UpdateFlags(ctx context.Context, id MessageID, add, remove []string) ([]string, error) {
	addF, err := ValidFlags(add)
	if err != nil {
		return nil, err
	}
	remF, err := ValidFlags(remove)
	if err != nil {
		return nil, err
	}
	if len(addF)+len(remF) == 0 {
		return nil, inputf("нужен хотя бы один флаг в add_flags или remove_flags")
	}
	var flags []string
	err = c.imapSession(ctx, func(cl *imapclient.Client) error {
		if _, err := openMessage(cl, id, false); err != nil {
			return err
		}
		set := imap.UIDSetNum(id.UID)
		if len(addF) > 0 {
			if err := cl.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: addF}, nil).Close(); err != nil {
				return err
			}
		}
		if len(remF) > 0 {
			if err := cl.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsDel, Silent: true, Flags: remF}, nil).Close(); err != nil {
				return err
			}
		}
		bufs, err := cl.Fetch(set, &imap.FetchOptions{UID: true, Flags: true}).Collect()
		if err != nil {
			return err
		}
		if len(bufs) == 0 {
			return notFoundf("письма %s нет", id)
		}
		flags = flagStrings(bufs[0].Flags)
		return nil
	})
	return flags, err
}

// TransferResult — итог копирования или переноса одного письма.
type TransferResult struct {
	MessageID    string `json:"message_id"`
	NewMessageID string `json:"new_message_id,omitempty"`
	Destination  string `json:"destination_mailbox"`
}

func newIDs(account, dest string, uv uint32, src []imap.UID, dst imap.NumSet) map[imap.UID]string {
	out := map[imap.UID]string{}
	ds, ok := dst.(imap.UIDSet)
	if !ok || uv == 0 {
		return out
	}
	nums, ok := ds.Nums()
	if !ok || len(nums) != len(src) {
		return out
	}
	// COPYUID перечисляет соответствие по порядку возрастания исходных UID.
	sorted := append([]imap.UID(nil), src...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	for i, s := range sorted {
		out[s] = MessageID{Account: account, Mailbox: dest, UIDValidity: uv, UID: nums[i]}.String()
	}
	return out
}

// Copy копирует письмо в папку этого же ящика.
func (c *Client) Copy(ctx context.Context, id MessageID, dest string) (TransferResult, error) {
	if err := ValidMailboxName(dest); err != nil {
		return TransferResult{}, err
	}
	res := TransferResult{MessageID: id.String()}
	err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		name, err := resolveMailbox(cl, dest)
		if err != nil {
			return err
		}
		res.Destination = name
		if _, err := openMessage(cl, id, true); err != nil {
			return err
		}
		data, err := cl.Copy(imap.UIDSetNum(id.UID), name).Wait()
		if err != nil {
			return err
		}
		if data != nil {
			res.NewMessageID = newIDs(c.acc.ID, name, data.UIDValidity, []imap.UID{id.UID}, data.DestUIDs)[id.UID]
		}
		return nil
	})
	return res, err
}

// Move переносит письмо в папку этого же ящика.
func (c *Client) Move(ctx context.Context, id MessageID, dest string) (TransferResult, error) {
	res, err := c.MoveMany(ctx, []MessageID{id}, dest)
	if err != nil {
		return TransferResult{}, err
	}
	if len(res.Failed) > 0 {
		return TransferResult{}, &Error{Kind: KindServer, Msg: res.Failed[0].Error}
	}
	if len(res.Done) == 0 {
		return TransferResult{}, notFoundf("письмо не перенесено")
	}
	return res.Done[0], nil
}

// BulkFailure — письмо, которое не удалось обработать.
type BulkFailure struct {
	MessageID string `json:"message_id"`
	Error     string `json:"error"`
}

// BulkResult — итог пакетной операции.
type BulkResult struct {
	Done   []TransferResult `json:"done,omitempty"`
	Failed []BulkFailure    `json:"failed,omitempty"`
}

// groupByMailbox — пакет может охватывать несколько папок; команды
// IMAP работают в пределах выбранной.
func groupByMailbox(ids []MessageID) (order []string, groups map[string][]MessageID) {
	groups = map[string][]MessageID{}
	for _, id := range ids {
		if _, ok := groups[id.Mailbox]; !ok {
			order = append(order, id.Mailbox)
		}
		groups[id.Mailbox] = append(groups[id.Mailbox], id)
	}
	return order, groups
}

func uidsOf(ids []MessageID) []imap.UID {
	out := make([]imap.UID, len(ids))
	for i, id := range ids {
		out[i] = id.UID
	}
	return out
}

func failAll(ids []MessageID, err error) []BulkFailure {
	out := make([]BulkFailure, len(ids))
	for i, id := range ids {
		out[i] = BulkFailure{MessageID: id.String(), Error: err.Error()}
	}
	return out
}

// MoveMany переносит письма. Ошибка одной папки не отменяет остальные.
func (c *Client) MoveMany(ctx context.Context, ids []MessageID, dest string) (BulkResult, error) {
	if err := ValidMailboxName(dest); err != nil {
		return BulkResult{}, err
	}
	var res BulkResult
	err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		name, err := resolveMailbox(cl, dest)
		if err != nil {
			return err
		}
		order, groups := groupByMailbox(ids)
		for _, mb := range order {
			group := groups[mb]
			if mb == name {
				res.Failed = append(res.Failed, failAll(group, fmt.Errorf("письмо уже в папке %q", name))...)
				continue
			}
			if _, err := openMessage(cl, group[0], false); err != nil {
				res.Failed = append(res.Failed, failAll(group, err)...)
				continue
			}
			data, err := cl.Move(imap.UIDSetNum(uidsOf(group)...), name).Wait()
			if err != nil {
				res.Failed = append(res.Failed, failAll(group, err)...)
				continue
			}
			var mapped map[imap.UID]string
			if data != nil {
				mapped = newIDs(c.acc.ID, name, data.UIDValidity, uidsOf(group), data.DestUIDs)
			}
			for _, id := range group {
				res.Done = append(res.Done, TransferResult{MessageID: id.String(), NewMessageID: mapped[id.UID], Destination: name})
			}
		}
		return nil
	})
	return res, err
}

// DeleteMode — как удалять.
type DeleteMode struct {
	// Permanent — стереть безвозвратно, минуя корзину.
	Permanent bool
}

// DeleteResult — итог удаления.
type DeleteResult struct {
	BulkResult
	// MovedToTrash — письма не стёрты, а перенесены в корзину.
	MovedToTrash string `json:"moved_to_trash,omitempty"`
}

// DeleteMany удаляет письма.
//
// По умолчанию — в корзину, как это делает любая почтовая программа:
// модель ошибается в выборе писем чаще, чем человек, и письмо в
// корзине можно вернуть. Безвозвратно — только по явному permanent,
// или если корзины нет, или письмо уже в ней.
func (c *Client) DeleteMany(ctx context.Context, ids []MessageID, mode DeleteMode) (DeleteResult, error) {
	var res DeleteResult
	err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		trash := ""
		if !mode.Permanent {
			var err error
			if trash, err = findRole(cl, RoleTrash); err != nil {
				return err
			}
		}
		order, groups := groupByMailbox(ids)
		for _, mb := range order {
			group := groups[mb]
			if _, err := openMessage(cl, group[0], false); err != nil {
				res.Failed = append(res.Failed, failAll(group, err)...)
				continue
			}
			set := imap.UIDSetNum(uidsOf(group)...)
			if trash != "" && mb != trash {
				data, err := cl.Move(set, trash).Wait()
				if err != nil {
					res.Failed = append(res.Failed, failAll(group, err)...)
					continue
				}
				var mapped map[imap.UID]string
				if data != nil {
					mapped = newIDs(c.acc.ID, trash, data.UIDValidity, uidsOf(group), data.DestUIDs)
				}
				for _, id := range group {
					res.Done = append(res.Done, TransferResult{MessageID: id.String(), NewMessageID: mapped[id.UID], Destination: trash})
				}
				res.MovedToTrash = trash
				continue
			}
			if err := expungeUIDs(cl, set); err != nil {
				res.Failed = append(res.Failed, failAll(group, err)...)
				continue
			}
			for _, id := range group {
				res.Done = append(res.Done, TransferResult{MessageID: id.String()})
			}
		}
		return nil
	})
	return res, err
}

// expungeUIDs стирает письма безвозвратно.
//
// UID EXPUNGE (UIDPLUS) стирает ровно эти письма. Без него остаётся
// обычный EXPUNGE, который заодно сотрёт всё, что в папке уже было
// помечено \Deleted другой программой, — это поведение протокола,
// и об этом честнее предупредить в описании инструмента, чем молчать.
func expungeUIDs(cl *imapclient.Client, set imap.UIDSet) error {
	if err := cl.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close(); err != nil {
		return err
	}
	if cl.Caps().Has(imap.CapUIDPlus) || cl.Caps().Has(imap.CapIMAP4rev2) {
		return cl.UIDExpunge(set).Close()
	}
	return cl.Expunge().Close()
}

// FlagsMany меняет флаги у нескольких писем.
func (c *Client) FlagsMany(ctx context.Context, ids []MessageID, add, remove []string) (BulkResult, error) {
	addF, err := ValidFlags(add)
	if err != nil {
		return BulkResult{}, err
	}
	remF, err := ValidFlags(remove)
	if err != nil {
		return BulkResult{}, err
	}
	if len(addF)+len(remF) == 0 {
		return BulkResult{}, inputf("нужен хотя бы один флаг в add_flags или remove_flags")
	}
	var res BulkResult
	err = c.imapSession(ctx, func(cl *imapclient.Client) error {
		order, groups := groupByMailbox(ids)
		for _, mb := range order {
			group := groups[mb]
			if _, err := openMessage(cl, group[0], false); err != nil {
				res.Failed = append(res.Failed, failAll(group, err)...)
				continue
			}
			set := imap.UIDSetNum(uidsOf(group)...)
			var opErr error
			if len(addF) > 0 {
				opErr = cl.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: addF}, nil).Close()
			}
			if opErr == nil && len(remF) > 0 {
				opErr = cl.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsDel, Silent: true, Flags: remF}, nil).Close()
			}
			if opErr != nil {
				res.Failed = append(res.Failed, failAll(group, opErr)...)
				continue
			}
			for _, id := range group {
				res.Done = append(res.Done, TransferResult{MessageID: id.String(), Destination: mb})
			}
		}
		return nil
	})
	return res, err
}

// SearchIDs — идентификаторы писем по условиям (для search_and_*).
func (c *Client) SearchIDs(ctx context.Context, mailbox string, crit Criteria, limit int) ([]MessageID, int, error) {
	if err := ValidMailboxName(mailbox); err != nil {
		return nil, 0, err
	}
	if crit.Empty() {
		return nil, 0, inputf("нужно хотя бы одно условие: без фильтра операция затронула бы всю папку")
	}
	if err := crit.Validate(); err != nil {
		return nil, 0, err
	}
	var (
		out   []MessageID
		total int
	)
	err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		name, err := resolveMailbox(cl, mailbox)
		if err != nil {
			return err
		}
		sel, err := cl.Select(name, &imap.SelectOptions{ReadOnly: true}).Wait()
		if err != nil {
			return err
		}
		uids, err := searchUIDs(cl, crit)
		if err != nil {
			return err
		}
		total = len(uids)
		if limit > 0 && len(uids) > limit {
			uids = uids[:limit]
		}
		for _, u := range uids {
			out = append(out, MessageID{Account: c.acc.ID, Mailbox: name, UIDValidity: sel.UIDValidity, UID: u})
		}
		return nil
	})
	return out, total, err
}

// AppendResult — итог записи письма в папку.
type AppendResult struct {
	Mailbox   string `json:"mailbox"`
	MessageID string `json:"message_id,omitempty"`
}

// Append кладёт готовое письмо в папку.
func (c *Client) Append(ctx context.Context, mailbox string, raw []byte, flags []imap.Flag) (AppendResult, error) {
	if err := ValidMailboxName(mailbox); err != nil {
		return AppendResult{}, err
	}
	var res AppendResult
	err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		name, err := resolveMailbox(cl, mailbox)
		if err != nil {
			return err
		}
		res.Mailbox = name
		id, err := appendTo(cl, c.acc.ID, name, raw, flags)
		res.MessageID = id
		return err
	})
	return res, err
}

func appendTo(cl *imapclient.Client, account, mailbox string, raw []byte, flags []imap.Flag) (string, error) {
	cmd := cl.Append(mailbox, int64(len(raw)), &imap.AppendOptions{Flags: flags, Time: time.Now()})
	if _, err := cmd.Write(raw); err != nil {
		cmd.Close()
		return "", err
	}
	if err := cmd.Close(); err != nil {
		return "", err
	}
	data, err := cmd.Wait()
	if err != nil {
		return "", err
	}
	if data != nil && data.UID != 0 && data.UIDValidity != 0 {
		return MessageID{Account: account, Mailbox: mailbox, UIDValidity: data.UIDValidity, UID: data.UID}.String(), nil
	}
	return "", nil
}
