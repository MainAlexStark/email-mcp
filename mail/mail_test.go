package mail_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"

	"github.com/MainAlexStark/email-mcp/mail"
	"github.com/MainAlexStark/email-mcp/mail/mailtest"
)

func setup(t *testing.T) (*mailtest.Server, *mail.Client) {
	t.Helper()
	srv := mailtest.Start(t)
	return srv, mail.New(srv.Account("work"))
}

func TestVerifyAndList(t *testing.T) {
	_, c := setup(t)
	ctx := context.Background()
	res, err := c.VerifyIMAP(ctx)
	if err != nil || !res.OK {
		t.Fatalf("verify: %v %+v", err, res)
	}
	boxes, err := c.ListMailboxes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if boxes[0].Name != "INBOX" {
		t.Fatalf("INBOX должен быть первым: %+v", boxes)
	}
	roles := map[string]string{}
	for _, b := range boxes {
		roles[b.Name] = b.Role
	}
	if roles["Sent"] != mail.RoleSent || roles["Drafts"] != mail.RoleDrafts || roles["Trash"] != mail.RoleTrash {
		t.Fatalf("роли папок не распознаны: %v", roles)
	}
	if _, err := c.VerifySMTP(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWrongPasswordIsAuthError(t *testing.T) {
	srv := mailtest.Start(t)
	acc := srv.Account("work")
	acc.Password = "nope"
	_, err := mail.New(acc).VerifyIMAP(context.Background())
	if mail.KindOf(err) != mail.KindAuth {
		t.Fatalf("ожидалась ошибка входа, получено %v (%s)", err, mail.KindOf(err))
	}
	if !strings.Contains(mail.Hint(err), "пароль") {
		t.Fatalf("подсказка не про пароль: %q", mail.Hint(err))
	}
}

func TestPublicOnlyBlocksLoopback(t *testing.T) {
	srv := mailtest.Start(t)
	_, err := mail.New(srv.Account("work"), mail.WithPublicOnly()).VerifyIMAP(context.Background())
	if err == nil || !strings.Contains(err.Error(), "внутреннюю сеть") {
		t.Fatalf("внутренний адрес должен быть запрещён: %v", err)
	}
	if srv.Logins() != 0 {
		t.Fatal("до сервера дошёл вход, хотя адрес запрещён")
	}
}

func TestSearchPagingAndGet(t *testing.T) {
	srv, c := setup(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		srv.Seed(t, "INBOX", mailtest.Message("Боб <bob@example.com>", mailtest.User, "Отчёт "+string(rune('A'+i)), "Привет, это тело письма"))
	}
	srv.Seed(t, "INBOX", mailtest.Message("eve@example.com", mailtest.User, "Другое", "x"))

	page, err := c.Search(ctx, "INBOX", mail.Criteria{From: "bob"}, mail.SearchOptions{Limit: 2, IncludeSnippet: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 5 || page.Returned != 2 || !page.HasMore || page.NextCursor == "" {
		t.Fatalf("первая страница: %+v", page)
	}
	if page.Messages[0].Subject != "Отчёт E" {
		t.Fatalf("новые письма должны идти первыми: %q", page.Messages[0].Subject)
	}
	if !strings.Contains(page.Messages[0].Snippet, "Привет") {
		t.Fatalf("нет фрагмента: %q", page.Messages[0].Snippet)
	}
	seen := map[string]bool{}
	for _, m := range page.Messages {
		seen[m.MessageID] = true
	}
	cursor := page.NextCursor
	for cursor != "" {
		p, err := c.Search(ctx, "", mail.Criteria{}, mail.SearchOptions{}, cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range p.Messages {
			if seen[m.MessageID] {
				t.Fatalf("письмо повторилось на следующей странице: %s", m.MessageID)
			}
			seen[m.MessageID] = true
		}
		cursor = p.NextCursor
	}
	if len(seen) != 5 {
		t.Fatalf("по страницам прошли %d писем из 5", len(seen))
	}

	id, _ := mail.ParseMessageID(page.Messages[0].MessageID)
	msg, err := c.GetMessage(ctx, id, mail.GetOptions{IncludeHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	if msg.Subject != "Отчёт E" || !strings.Contains(msg.BodyText, "тело письма") {
		t.Fatalf("письмо прочитано неверно: %+v", msg)
	}
}

func TestCursorFromOtherAccountRejected(t *testing.T) {
	srv, c := setup(t)
	srv.Seed(t, "INBOX", mailtest.Message("a@b.c", mailtest.User, "1", "x"))
	srv.Seed(t, "INBOX", mailtest.Message("a@b.c", mailtest.User, "2", "x"))
	page, err := c.Search(context.Background(), "INBOX", mail.Criteria{}, mail.SearchOptions{Limit: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	other := mail.New(srv.Account("home"))
	if _, err := other.Search(context.Background(), "", mail.Criteria{}, mail.SearchOptions{}, page.NextCursor); !mail.IsInput(err) {
		t.Fatalf("курсор чужого ящика должен отклоняться: %v", err)
	}
}

func TestStaleUIDValidity(t *testing.T) {
	srv, c := setup(t)
	uid := srv.Seed(t, "INBOX", mailtest.Message("a@b.c", mailtest.User, "1", "x"))
	id := mail.MessageID{Account: "work", Mailbox: "INBOX", UIDValidity: 999999, UID: uid}
	if _, err := c.GetMessage(context.Background(), id, mail.GetOptions{}); mail.KindOf(err) != mail.KindNotFound {
		t.Fatalf("устаревший uidvalidity должен давать not_found: %v", err)
	}
}

func TestMoveDeleteToTrashAndFlags(t *testing.T) {
	srv, c := setup(t)
	ctx := context.Background()
	srv.Seed(t, "INBOX", mailtest.Message("a@b.c", mailtest.User, "Переносимое", "x"))
	srv.Seed(t, "INBOX", mailtest.Message("a@b.c", mailtest.User, "Удаляемое", "x"))

	ids, _, err := c.SearchIDs(ctx, "INBOX", mail.Criteria{Subject: "Переносимое"}, 10)
	if err != nil || len(ids) != 1 {
		t.Fatalf("поиск: %v %v", ids, err)
	}
	moved, err := c.Move(ctx, ids[0], "Archive")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(moved.NewMessageID, ":Archive:") {
		t.Fatalf("после переноса нужен новый id: %+v", moved)
	}
	newID, _ := mail.ParseMessageID(moved.NewMessageID)
	flags, err := c.UpdateFlags(ctx, newID, []string{`\flagged`, "важное"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(flags, string(imap.FlagFlagged)) || !contains(flags, "важное") {
		t.Fatalf("флаги не поставлены: %v", flags)
	}

	ids, _, _ = c.SearchIDs(ctx, "INBOX", mail.Criteria{Subject: "Удаляемое"}, 10)
	del, err := c.DeleteMany(ctx, ids, mail.DeleteMode{})
	if err != nil || len(del.Done) != 1 || del.MovedToTrash != "Trash" {
		t.Fatalf("удаление по умолчанию должно уводить в корзину: %+v %v", del, err)
	}
	st, _ := c.Status(ctx, "Trash")
	if st.Messages != 1 {
		t.Fatalf("в корзине %d писем", st.Messages)
	}
	trashID, _ := mail.ParseMessageID(del.Done[0].NewMessageID)
	del, err = c.DeleteMany(ctx, []mail.MessageID{trashID}, mail.DeleteMode{})
	if err != nil || len(del.Done) != 1 || del.MovedToTrash != "" {
		t.Fatalf("из корзины удаляется безвозвратно: %+v %v", del, err)
	}
	st, _ = c.Status(ctx, "Trash")
	if st.Messages != 0 {
		t.Fatalf("корзина не очищена: %d", st.Messages)
	}
}

func TestSendSavesCopyAndStripsBcc(t *testing.T) {
	srv, c := setup(t)
	ctx := context.Background()
	res, err := c.Send(ctx, mail.Outgoing{
		To: []string{"Боб <bob@example.com>"}, Bcc: []string{"secret@example.com"},
		Subject: "Счёт за октябрь", Text: "Во вложении счёт.",
		Attach: []mail.OutAttachment{{Filename: "счёт.txt", Data: []byte("итого 100")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.SavedToSent || res.SentMailbox != "Sent" {
		t.Fatalf("копия не сохранена: %+v", res)
	}
	sent := srv.SentMessages()
	if len(sent) != 1 || len(sent[0].To) != 2 {
		t.Fatalf("конверт: %+v", sent)
	}
	if strings.Contains(string(sent[0].Data), "secret@example.com") {
		t.Fatal("Bcc попал в заголовки отправленного письма")
	}
	if !strings.Contains(string(sent[0].Data), "Message-Id: <") || !strings.Contains(res.MessageID, "@example.com>") {
		t.Fatalf("Message-ID должен быть на домене отправителя: %s", res.MessageID)
	}
	p, err := mail.Parse(sent[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "Счёт за октябрь" || len(p.Attachments()) != 1 || p.Attachments()[0].Filename != "счёт.txt" {
		t.Fatalf("письмо собрано неверно: %q %+v", p.Subject, p.Attachments())
	}
}

func TestReplyThreadsAndMarksAnswered(t *testing.T) {
	srv, c := setup(t)
	ctx := context.Background()
	srv.Seed(t, "INBOX", "From: Bob <bob@example.com>\nTo: alex@example.com\nCc: carol@example.com\n"+
		"Subject: Вопрос\nMessage-ID: <q1@example.com>\nContent-Type: text/plain; charset=utf-8\n\nКогда встреча?\n")
	ids, _, _ := c.SearchIDs(ctx, "INBOX", mail.Criteria{Subject: "Вопрос"}, 1)
	if _, err := c.Reply(ctx, ids[0], mail.ReplyOptions{Text: "Завтра в 10.", ReplyAll: true}); err != nil {
		t.Fatal(err)
	}
	sent := srv.SentMessages()
	p, _ := mail.Parse(sent[0].Data)
	if p.Subject != "Re: Вопрос" || p.Header.Get("In-Reply-To") != "<q1@example.com>" {
		t.Fatalf("ответ не встал в цепочку: %q %q", p.Subject, p.Header.Get("In-Reply-To"))
	}
	if !strings.Contains(p.Text, "> Когда встреча?") {
		t.Fatalf("нет цитаты: %q", p.Text)
	}
	if len(sent[0].To) != 2 {
		t.Fatalf("ответ всем должен уйти Бобу и Кэрол, без себя: %v", sent[0].To)
	}
	msg, _ := c.GetMessage(ctx, ids[0], mail.GetOptions{})
	if !contains(msg.Flags, string(imap.FlagAnswered)) {
		t.Fatalf("исходное письмо не помечено отвеченным: %v", msg.Flags)
	}
}

func TestDraftsLifecycle(t *testing.T) {
	srv, c := setup(t)
	ctx := context.Background()
	d, err := c.CreateDraft(ctx, mail.Outgoing{To: []string{"bob@example.com"}, Bcc: []string{"boss@example.com"},
		Subject: "Черновик", Text: "v1"})
	if err != nil || d.DraftID == "" {
		t.Fatalf("черновик: %+v %v", d, err)
	}
	id, _ := mail.ParseMessageID(d.DraftID)
	d2, err := c.UpdateDraft(ctx, id, mail.Outgoing{To: []string{"bob@example.com"}, Bcc: []string{"boss@example.com"},
		Subject: "Черновик", Text: "v2"})
	if err != nil || !d2.PreviousDraftRemoved {
		t.Fatalf("правка черновика: %+v %v", d2, err)
	}
	list, _ := c.ListDrafts(ctx, 10)
	if len(list) != 1 || list[0].DraftID != d2.DraftID {
		t.Fatalf("в черновиках должна быть одна версия: %+v", list)
	}

	// Письмо не из черновиков draft-инструментами не трогается.
	srv.Seed(t, "INBOX", mailtest.Message("a@b.c", mailtest.User, "Не черновик", "x"))
	inbox, _, _ := c.SearchIDs(ctx, "INBOX", mail.Criteria{Subject: "Не черновик"}, 1)
	if err := c.DeleteDraft(ctx, inbox[0]); !mail.IsInput(err) {
		t.Fatalf("draft_delete по письму из INBOX должен отказать: %v", err)
	}

	id2, _ := mail.ParseMessageID(d2.DraftID)
	res, err := c.SendDraft(ctx, id2)
	if err != nil || !res.DraftRemoved {
		t.Fatalf("отправка черновика: %+v %v", res, err)
	}
	sent := srv.SentMessages()
	if len(sent) != 1 || len(sent[0].To) != 2 || strings.Contains(string(sent[0].Data), "boss@example.com") {
		t.Fatalf("черновик ушёл неверно: %+v", sent)
	}
	if list, _ := c.ListDrafts(ctx, 10); len(list) != 0 {
		t.Fatalf("черновик не удалён после отправки: %+v", list)
	}
}

func TestSearchAll(t *testing.T) {
	srv, c := setup(t)
	srv.Seed(t, "INBOX", mailtest.Message("bob@example.com", mailtest.User, "Проект Альфа", "x"))
	srv.Seed(t, "Sent", mailtest.Message(mailtest.User, "bob@example.com", "Re: Проект Альфа", "y"))
	srv.Seed(t, "Archive", mailtest.Message("eve@example.com", mailtest.User, "Не то", "z"))
	res, err := c.SearchAll(context.Background(), mail.Criteria{Subject: "Альфа"}, mail.SearchAllOptions{Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 2 || len(res.Failed) != 0 {
		t.Fatalf("поиск по всем папкам: %+v", res)
	}
	boxes := map[string]bool{}
	for _, m := range res.Messages {
		boxes[m.Mailbox] = true
	}
	if !boxes["INBOX"] || !boxes["Sent"] {
		t.Fatalf("переписка должна найтись в обеих папках: %+v", res.Messages)
	}
}

func TestParseAttachmentsAndCharset(t *testing.T) {
	raw := "From: a@b.c\r\nSubject: =?koi8-r?B?8NLJ18XU?=\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\nContent-Type: text/plain; charset=windows-1251\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte{0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2}) +
		"\r\n--XX\r\nContent-Type: application/octet-stream; name=\"a.bin\"\r\nContent-Disposition: attachment; filename=\"a.bin\"\r\n\r\nbinary\r\n--XX--\r\n"
	p, err := mail.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "Привет" {
		t.Fatalf("тема koi8-r: %q", p.Subject)
	}
	if strings.TrimSpace(p.Text) != "Привет" {
		t.Fatalf("тело windows-1251: %q", p.Text)
	}
	a, err := p.FindPart("2", "")
	if err != nil || a.Filename != "a.bin" {
		t.Fatalf("вложение 2: %+v %v", a, err)
	}
}

func TestMessageIDWithColons(t *testing.T) {
	id, err := mail.ParseMessageID("imap:work:Projects:2026:Q1:42:7")
	if err != nil || id.Mailbox != "Projects:2026:Q1" || id.UIDValidity != 42 || id.UID != 7 {
		t.Fatalf("%+v %v", id, err)
	}
	if _, err := mail.ParseMessageIDFor(id.String(), "home"); !mail.IsInput(err) {
		t.Fatal("id другого ящика должен отклоняться")
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
