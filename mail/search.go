package mail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// Criteria — условия поиска. Пустые поля не участвуют.
type Criteria struct {
	Query           string `json:"q,omitempty"`
	From            string `json:"f,omitempty"`
	To              string `json:"t,omitempty"`
	Subject         string `json:"s,omitempty"`
	ThreadMessageID string `json:"th,omitempty"`
	UnreadOnly      bool   `json:"u,omitempty"`
	LastDays        int    `json:"ld,omitempty"`
	StartDate       string `json:"sd,omitempty"` // YYYY-MM-DD
	EndDate         string `json:"ed,omitempty"` // YYYY-MM-DD, включительно
}

// Empty — ни одного условия.
func (c Criteria) Empty() bool { return c == Criteria{} }

// MaxSearchMatches — больше совпадений поиск не разбирает: такой
// запрос почти всегда означает «забыли фильтр», а выгрузка
// идентификаторов ста тысяч писем стоит минуты и ничего не даёт модели.
const MaxSearchMatches = 20_000

// Validate проверяет условия до похода на сервер.
func (c Criteria) Validate() error {
	for name, v := range map[string]string{
		"query": c.Query, "from": c.From, "to": c.To, "subject": c.Subject, "thread_message_id": c.ThreadMessageID,
	} {
		if len(v) > 256 {
			return inputf("%s длиннее 256 символов", name)
		}
		for _, r := range v {
			if unicode.IsControl(r) {
				return inputf("%s содержит управляющие символы", name)
			}
		}
	}
	if c.ThreadMessageID != "" && strings.ContainsAny(c.ThreadMessageID, " \t") {
		return inputf("thread_message_id — один Message-ID вида <id@host>, без пробелов")
	}
	if c.LastDays != 0 && (c.LastDays < 1 || c.LastDays > 3650) {
		return inputf("last_days — от 1 до 3650")
	}
	if c.LastDays != 0 && (c.StartDate != "" || c.EndDate != "") {
		return inputf("last_days нельзя сочетать со start_date/end_date: выберите что-то одно")
	}
	start, err := parseDay(c.StartDate, "start_date")
	if err != nil {
		return err
	}
	end, err := parseDay(c.EndDate, "end_date")
	if err != nil {
		return err
	}
	if !start.IsZero() && !end.IsZero() && start.After(end) {
		return inputf("start_date позже end_date")
	}
	return nil
}

func parseDay(s, field string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, inputf("%s в формате ГГГГ-ММ-ДД, получено %q", field, s)
	}
	return t, nil
}

// bracketed приводит Message-ID к виду <id@host>: iCloud ищет по
// заголовкам целыми словами и без скобок не находит ничего.
func bracketed(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "<")
	id = strings.TrimSuffix(id, ">")
	return "<" + id + ">"
}

func (c Criteria) imap(now time.Time) *imap.SearchCriteria {
	sc := &imap.SearchCriteria{}
	if c.Query != "" {
		sc.Text = []string{c.Query}
	}
	if c.From != "" {
		sc.Header = append(sc.Header, imap.SearchCriteriaHeaderField{Key: "From", Value: c.From})
	}
	if c.To != "" {
		sc.Header = append(sc.Header, imap.SearchCriteriaHeaderField{Key: "To", Value: c.To})
	}
	if c.Subject != "" {
		sc.Header = append(sc.Header, imap.SearchCriteriaHeaderField{Key: "Subject", Value: c.Subject})
	}
	if c.UnreadOnly {
		sc.NotFlag = []imap.Flag{imap.FlagSeen}
	}
	if c.LastDays > 0 {
		sc.Since = now.AddDate(0, 0, -c.LastDays)
	}
	if t, _ := parseDay(c.StartDate, ""); !t.IsZero() {
		sc.Since = t
	}
	if t, _ := parseDay(c.EndDate, ""); !t.IsZero() {
		// BEFORE не включает день, а end_date по смыслу включительно.
		sc.Before = t.AddDate(0, 0, 1)
	}
	if c.ThreadMessageID != "" {
		id := bracketed(c.ThreadMessageID)
		h := func(k string) imap.SearchCriteria {
			return imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: k, Value: id}}}
		}
		sc.Or = append(sc.Or,
			[2]imap.SearchCriteria{h("Message-ID"), {Or: [][2]imap.SearchCriteria{{h("In-Reply-To"), h("References")}}}})
	}
	return sc
}

// Summary — письмо в результатах поиска.
type Summary struct {
	MessageID   string   `json:"message_id"`
	Mailbox     string   `json:"mailbox"`
	UIDValidity uint32   `json:"uidvalidity"`
	UID         uint32   `json:"uid"`
	Date        string   `json:"date,omitempty"`
	From        string   `json:"from,omitempty"`
	To          string   `json:"to,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Flags       []string `json:"flags,omitempty"`
	Size        int64    `json:"size_bytes,omitempty"`
	Snippet     string   `json:"snippet,omitempty"`

	date time.Time
}

// SearchOptions — как отдавать результат.
type SearchOptions struct {
	Limit           int
	IncludeSnippet  bool
	SnippetMaxChars int
}

// SearchResult — страница результатов.
type SearchResult struct {
	Mailbox    string    `json:"mailbox"`
	Total      int       `json:"total"`
	Returned   int       `json:"returned"`
	Messages   []Summary `json:"messages"`
	HasMore    bool      `json:"has_more"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

// cursorState — всё, что нужно, чтобы продолжить поиск без состояния
// на сервере. Сервер MCP без сессий и переживает перезапуск, поэтому
// курсор несёт условия с собой, а не номер записи в памяти процесса.
type cursorState struct {
	V        int      `json:"v"`
	Account  string   `json:"a"`
	Mailbox  string   `json:"m"`
	UV       uint32   `json:"uv"`
	Before   uint32   `json:"b"`
	Criteria Criteria `json:"c"`
	Snippet  bool     `json:"sn,omitempty"`
	SnipMax  int      `json:"sm,omitempty"`
	Limit    int      `json:"l"`
}

func encodeCursor(s cursorState) string {
	b, _ := json.Marshal(s)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(raw, account string) (cursorState, error) {
	var s cursorState
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(b, &s) != nil || s.V != 1 {
		return s, inputf("cursor не разобран: передавайте next_cursor из предыдущего ответа без изменений")
	}
	if s.Account != account {
		return s, inputf("cursor получен для ящика %q, а вызов — для %q", s.Account, account)
	}
	return s, nil
}

// Search ищет в одной папке, новые письма первыми.
//
// cursor != "" продолжает предыдущий поиск: условия, папка и лимит
// берутся из него, mailbox и criteria игнорируются вызывающим кодом.
func (c *Client) Search(ctx context.Context, mailbox string, crit Criteria, opt SearchOptions, cursor string) (SearchResult, error) {
	st := cursorState{V: 1, Account: c.acc.ID, Mailbox: mailbox, Criteria: crit,
		Snippet: opt.IncludeSnippet, SnipMax: opt.SnippetMaxChars, Limit: opt.Limit}
	if cursor != "" {
		var err error
		if st, err = decodeCursor(cursor, c.acc.ID); err != nil {
			return SearchResult{}, err
		}
	} else {
		if err := ValidMailboxName(mailbox); err != nil {
			return SearchResult{}, err
		}
		if err := crit.Validate(); err != nil {
			return SearchResult{}, err
		}
	}
	if st.Limit <= 0 {
		st.Limit = 10
	}

	var res SearchResult
	err := c.imapSession(ctx, func(cl *imapclient.Client) error {
		name, err := resolveMailbox(cl, st.Mailbox)
		if err != nil {
			return err
		}
		sel, err := cl.Select(name, &imap.SelectOptions{ReadOnly: true}).Wait()
		if err != nil {
			return err
		}
		if cursor != "" && st.UV != 0 && sel.UIDValidity != st.UV {
			return &Error{Kind: KindNotFound, Msg: "папка изменилась после первого запроса (uidvalidity), начните поиск заново"}
		}
		uids, err := searchUIDs(cl, st.Criteria)
		if err != nil {
			return err
		}
		res.Mailbox = name
		res.Total = len(uids)

		if st.Before > 0 {
			i := sort.Search(len(uids), func(i int) bool { return uids[i] < imap.UID(st.Before) })
			uids = uids[i:]
		}
		page := uids
		if len(page) > st.Limit {
			page = page[:st.Limit]
		}
		res.HasMore = len(uids) > len(page)

		msgs, err := fetchSummaries(cl, c.acc.ID, name, sel.UIDValidity, page, st.Snippet, st.SnipMax)
		if err != nil {
			return err
		}
		res.Messages = msgs
		res.Returned = len(msgs)
		if res.HasMore && len(page) > 0 {
			next := st
			next.Mailbox = name
			next.UV = sel.UIDValidity
			next.Before = uint32(page[len(page)-1])
			res.NextCursor = encodeCursor(next)
		}
		return nil
	})
	return res, err
}

// searchUIDs — UID найденных писем, по убыванию (новые первыми).
func searchUIDs(cl *imapclient.Client, crit Criteria) ([]imap.UID, error) {
	sc := crit.imap(time.Now())
	data, err := cl.UIDSearch(sc, nil).Wait()
	if err != nil {
		return nil, err
	}
	uids := data.AllUIDs()
	if len(uids) > MaxSearchMatches {
		return nil, inputf("под условия попало %d писем — больше %d. Сузьте поиск: last_days, from, subject",
			len(uids), MaxSearchMatches)
	}
	slices.Sort(uids)
	slices.Reverse(uids)
	return uids, nil
}

// snippetBytes — сколько байт письма читать ради фрагмента. Текст
// почти всегда в первой части, а качать письмо с вложениями целиком
// ради двухсот символов — расточительство, заметное на списке из 50.
const snippetBytes = 16 << 10

func fetchSummaries(cl *imapclient.Client, account, mailbox string, uv uint32, uids []imap.UID, snippet bool, snipMax int) ([]Summary, error) {
	if len(uids) == 0 {
		return []Summary{}, nil
	}
	opts := &imap.FetchOptions{UID: true, Envelope: true, Flags: true, RFC822Size: true}
	section := &imap.FetchItemBodySection{Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: snippetBytes}}
	if snippet {
		opts.BodySection = []*imap.FetchItemBodySection{section}
	}
	bufs, err := cl.Fetch(imap.UIDSetNum(uids...), opts).Collect()
	if err != nil {
		return nil, err
	}
	byUID := make(map[imap.UID]*imapclient.FetchMessageBuffer, len(bufs))
	for _, b := range bufs {
		byUID[b.UID] = b
	}
	out := make([]Summary, 0, len(uids))
	for _, uid := range uids { // порядок поиска, а не порядок ответа сервера
		b, ok := byUID[uid]
		if !ok {
			continue // письмо удалили между SEARCH и FETCH
		}
		s := summaryFrom(account, mailbox, uv, b)
		if snippet {
			if raw := b.FindBodySection(section); raw != nil {
				s.Snippet = Snippet(raw, snipMax)
			}
		}
		out = append(out, s)
	}
	return out, nil
}

func summaryFrom(account, mailbox string, uv uint32, b *imapclient.FetchMessageBuffer) Summary {
	s := Summary{
		MessageID:   MessageID{Account: account, Mailbox: mailbox, UIDValidity: uv, UID: b.UID}.String(),
		Mailbox:     mailbox,
		UIDValidity: uv,
		UID:         uint32(b.UID),
		Size:        b.RFC822Size,
		Flags:       flagStrings(b.Flags),
	}
	if e := b.Envelope; e != nil {
		s.Subject = e.Subject
		s.From = formatAddrs(e.From)
		s.To = formatAddrs(e.To)
		if !e.Date.IsZero() {
			s.date = e.Date
			s.Date = e.Date.Format(time.RFC3339)
		}
	}
	if s.date.IsZero() && !b.InternalDate.IsZero() {
		s.date = b.InternalDate
	}
	return s
}

func flagStrings(fl []imap.Flag) []string {
	out := make([]string, 0, len(fl))
	for _, f := range fl {
		out = append(out, string(f))
	}
	return out
}

func formatAddrs(list []imap.Address) string {
	parts := make([]string, 0, len(list))
	for i := range list {
		a := &list[i]
		if a.IsGroupStart() || a.IsGroupEnd() {
			continue
		}
		addr := a.Addr()
		if a.Name != "" {
			parts = append(parts, fmt.Sprintf("%s <%s>", a.Name, addr))
		} else {
			parts = append(parts, addr)
		}
	}
	return strings.Join(parts, ", ")
}

// SearchAllOptions — поиск по всем папкам.
type SearchAllOptions struct {
	SearchOptions
	Include     []string
	Exclude     []string
	Concurrency int
}

// SearchAllResult — итог поиска по всем папкам.
type SearchAllResult struct {
	InScope   []string          `json:"mailboxes_in_scope"`
	Searched  []string          `json:"mailboxes_searched"`
	Failed    map[string]string `json:"mailboxes_failed,omitempty"`
	Total     int               `json:"total"`
	Returned  int               `json:"returned"`
	Truncated bool              `json:"truncated"`
	Messages  []Summary         `json:"messages"`
}

func underAny(name string, roots []string, delim string) bool {
	for _, r := range roots {
		if name == r || (delim != "" && strings.HasPrefix(name, r+delim)) {
			return true
		}
	}
	return false
}

// SearchAll ищет во всех открываемых папках сразу.
//
// Нужен там, где переписка разложена по папкам и общей «Вся почта» нет
// (iCloud, Яндекс): ответ лежит во «Входящих», своё письмо — в
// «Отправленных». Отказ одной папки не обрывает поиск: он попадает в
// mailboxes_failed, остальное возвращается.
func (c *Client) SearchAll(ctx context.Context, crit Criteria, opt SearchAllOptions) (SearchAllResult, error) {
	if crit.Empty() {
		return SearchAllResult{}, inputf("нужно хотя бы одно условие поиска: по всем папкам без фильтра искать бессмысленно")
	}
	if err := crit.Validate(); err != nil {
		return SearchAllResult{}, err
	}
	if opt.Limit <= 0 {
		opt.Limit = 50
	}
	if opt.Concurrency < 1 {
		opt.Concurrency = 4
	}
	if opt.Concurrency > 8 {
		opt.Concurrency = 8
	}

	list, err := c.ListMailboxes(ctx)
	if err != nil {
		return SearchAllResult{}, err
	}
	res := SearchAllResult{Failed: map[string]string{}}
	for _, mb := range list {
		if mb.NoSelect {
			continue
		}
		if len(opt.Include) > 0 && !underAny(mb.Name, opt.Include, mb.Delimiter) {
			continue
		}
		if underAny(mb.Name, opt.Exclude, mb.Delimiter) {
			continue
		}
		res.InScope = append(res.InScope, mb.Name)
	}
	if len(res.InScope) == 0 {
		res.Messages = []Summary{}
		return res, nil
	}

	// Папки делятся между несколькими соединениями: по одному на папку
	// — это сотня входов подряд и блокировка за подозрительную
	// активность, одно на всё — минуты ожидания на большом ящике.
	// Распределяем заранее: так каждое соединение открывается один раз
	// на свою пачку папок, а не на каждую папку.
	workers := min(opt.Concurrency, len(res.InScope))
	var (
		mu  sync.Mutex
		all []Summary
		wg  sync.WaitGroup
	)
	buckets := make([][]string, workers)
	for i, name := range res.InScope {
		buckets[i%workers] = append(buckets[i%workers], name)
	}
	for _, bucket := range buckets {
		wg.Add(1)
		go func(names []string) {
			defer wg.Done()
			done := map[string]bool{}
			err := c.imapSession(ctx, func(cl *imapclient.Client) error {
				for _, name := range names {
					found, total, err := searchOne(cl, c.acc.ID, name, crit, opt.SearchOptions)
					mu.Lock()
					if err != nil {
						res.Failed[name] = err.Error()
					} else {
						res.Searched = append(res.Searched, name)
						res.Total += total
						all = append(all, found...)
					}
					done[name] = true
					mu.Unlock()
				}
				return nil
			})
			if err != nil {
				mu.Lock()
				for _, name := range names {
					if !done[name] {
						res.Failed[name] = err.Error()
					}
				}
				mu.Unlock()
			}
		}(bucket)
	}
	wg.Wait()

	if len(res.Searched) == 0 && len(res.Failed) > 0 {
		for _, msg := range res.Failed {
			return res, &Error{Kind: KindServer, Msg: "ни одна папка не ответила: " + msg}
		}
	}

	sort.SliceStable(all, func(i, j int) bool { return all[i].date.After(all[j].date) })
	if len(all) > opt.Limit {
		all = all[:opt.Limit]
	}
	if all == nil {
		all = []Summary{}
	}
	sort.Strings(res.Searched)
	res.Messages = all
	res.Returned = len(all)
	res.Truncated = res.Total > res.Returned
	if len(res.Failed) == 0 {
		res.Failed = nil
	}
	return res, nil
}

func searchOne(cl *imapclient.Client, account, name string, crit Criteria, opt SearchOptions) ([]Summary, int, error) {
	sel, err := cl.Select(name, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return nil, 0, err
	}
	if sel.NumMessages == 0 {
		return nil, 0, nil
	}
	uids, err := searchUIDs(cl, crit)
	if err != nil {
		return nil, 0, err
	}
	total := len(uids)
	if len(uids) > opt.Limit {
		uids = uids[:opt.Limit]
	}
	msgs, err := fetchSummaries(cl, account, name, sel.UIDValidity, uids, opt.IncludeSnippet, opt.SnippetMaxChars)
	return msgs, total, err
}
