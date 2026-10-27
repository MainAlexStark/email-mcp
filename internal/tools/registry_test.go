package tools

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MainAlexStark/email-mcp/internal/mcp"
	"github.com/MainAlexStark/email-mcp/internal/mcptest"
	"github.com/MainAlexStark/email-mcp/mail"
	"github.com/MainAlexStark/email-mcp/mail/mailtest"
)

// newServer собирает сервер со всеми инструментами поверх настоящих
// IMAP и SMTP в памяти. Тесты ниже проходят весь путь целиком:
// tools/call → защита → клиент ящика → протокол.
func newServer(t *testing.T, safety Safety, accounts ...mail.Account) *mcp.Server {
	t.Helper()
	srv := mcp.NewServer("test", "0.0.1")
	reg := NewRegistry(Config{Accounts: accounts}, safety, srv)
	RegisterAll(reg)
	return srv
}

func call(t *testing.T, srv *mcp.Server, name string, args any) mcptest.Result {
	t.Helper()
	sess, err := mcptest.Start(srv)
	if err != nil {
		t.Fatalf("сессия не поднялась: %v", err)
	}
	defer sess.Close()
	res, err := sess.Call(name, args)
	if err != nil {
		t.Fatalf("вызов %s: %v", name, err)
	}
	return res
}

func allowAll() Safety {
	s := DefaultSafety()
	s.Drafts, s.Write, s.Send = true, true, true
	return s
}

func TestReadOnlyByDefaultNothingReachesServer(t *testing.T) {
	box := mailtest.Start(t)
	srv := newServer(t, DefaultSafety(), box.Account("work"))

	cases := []struct {
		tool string
		args map[string]any
	}{
		{"smtp_send_message", map[string]any{"to": []string{"bob@example.com"}, "subject": "x", "body_text": "y"}},
		{"imap_create_mailbox", map[string]any{"mailbox_name": "Новая"}},
		{"imap_delete_message", map[string]any{"message_id": "imap:work:INBOX:1:1", "confirm": true}},
		{"draft_create", map[string]any{"to": []string{"bob@example.com"}, "subject": "x", "body_text": "y"}},
		{"imap_bulk_move", map[string]any{"message_ids": []string{"imap:work:INBOX:1:1"}, "destination_mailbox": "Archive"}},
	}
	for _, c := range cases {
		res := call(t, srv, c.tool, c.args)
		if !res.IsError || !strings.Contains(res.Text, "нужно право") {
			t.Errorf("%s в режиме чтения должен отказывать: %q", c.tool, res.Text)
		}
		// Текст отказа обязан называть оба способа починки.
		if !strings.Contains(res.Text, "MAIL_ALLOW_") || !strings.Contains(res.Text, "экране согласия") {
			t.Errorf("%s: отказ не объясняет, где открыть право: %q", c.tool, res.Text)
		}
	}
	if box.Logins() != 0 || len(box.SentMessages()) != 0 {
		t.Fatalf("запрос дошёл до почтового сервера вопреки отказу: входов %d, писем %d",
			box.Logins(), len(box.SentMessages()))
	}
}

func TestPermissionsAreIndependent(t *testing.T) {
	box := mailtest.Start(t)
	s := DefaultSafety()
	s.Drafts = true
	srv := newServer(t, s, box.Account("work"))

	res := call(t, srv, "draft_create", map[string]any{"to": []string{"bob@example.com"}, "subject": "x", "body_text": "y"})
	if res.IsError {
		t.Fatalf("черновик с правом черновиков должен создаваться: %s", res.Text)
	}
	var out struct {
		Result mail.DraftResult `json:"result"`
	}
	_ = json.Unmarshal([]byte(res.Text), &out)

	// Право на черновики не даёт отправить черновик.
	res = call(t, srv, "draft_send", map[string]any{"draft_id": out.Result.DraftID})
	if !res.IsError || !strings.Contains(res.Text, "Отправка") {
		t.Fatalf("draft_send без права отправки должен отказывать: %s", res.Text)
	}
	if len(box.SentMessages()) != 0 {
		t.Fatal("письмо ушло без права на отправку")
	}
}

func TestSendAndSearchEndToEnd(t *testing.T) {
	box := mailtest.Start(t)
	box.Seed(t, "INBOX", mailtest.Message("Боб <bob@example.com>", mailtest.User, "Счёт", "Пришлите акт."))
	srv := newServer(t, allowAll(), box.Account("work"))

	res := call(t, srv, "imap_search_messages", map[string]any{"mailbox": "INBOX", "from": "bob"})
	if res.IsError {
		t.Fatal(res.Text)
	}
	var found struct {
		Result mail.SearchResult `json:"result"`
	}
	if err := json.Unmarshal([]byte(res.Text), &found); err != nil || found.Result.Total != 1 {
		t.Fatalf("поиск: %v %s", err, res.Text)
	}
	id := found.Result.Messages[0].MessageID

	res = call(t, srv, "smtp_reply_message", map[string]any{"message_id": id, "body_text": "Высылаю."})
	if res.IsError {
		t.Fatal(res.Text)
	}
	sent := box.SentMessages()
	if len(sent) != 1 || sent[0].To[0] != "bob@example.com" {
		t.Fatalf("ответ не ушёл Бобу: %+v", sent)
	}
}

func TestManyRecipientsNeedConfirmation(t *testing.T) {
	box := mailtest.Start(t)
	s := allowAll()
	s.MaxRecipients = 2
	srv := newServer(t, s, box.Account("work"))
	args := map[string]any{"to": []string{"a@x.ru", "b@x.ru", "c@x.ru"}, "subject": "Всем", "body_text": "Привет"}

	res := call(t, srv, "smtp_send_message", args)
	if !res.IsError || !strings.Contains(res.Text, "confirm_many_recipients") {
		t.Fatalf("три адреса при пороге 2 без подтверждения: %s", res.Text)
	}
	if len(box.SentMessages()) != 0 {
		t.Fatal("письмо ушло без подтверждения")
	}
	args["confirm_many_recipients"] = true
	if res := call(t, srv, "smtp_send_message", args); res.IsError {
		t.Fatal(res.Text)
	}
	if len(box.SentMessages()) != 1 {
		t.Fatal("с подтверждением письмо должно уйти")
	}
}

func TestDeleteNeedsConfirmAndBatchLimit(t *testing.T) {
	box := mailtest.Start(t)
	s := allowAll()
	s.MaxItemsPerWrite = 2
	srv := newServer(t, s, box.Account("work"))

	res := call(t, srv, "imap_delete_message", map[string]any{"message_id": "imap:work:INBOX:1:1"})
	if !res.IsError || !strings.Contains(res.Text, "confirm") {
		t.Fatalf("удаление без confirm: %s", res.Text)
	}
	ids := []string{"imap:work:INBOX:1:1", "imap:work:INBOX:1:2", "imap:work:INBOX:1:3"}
	res = call(t, srv, "imap_bulk_update_flags", map[string]any{"message_ids": ids, "add_flags": []string{`\Seen`}})
	if !res.IsError || !strings.Contains(res.Text, "не более 2") {
		t.Fatalf("пакет больше порога: %s", res.Text)
	}
	if box.Logins() != 0 {
		t.Fatal("до сервера дошёл запрос, остановленный защитой")
	}
}

func TestAccountSelection(t *testing.T) {
	box := mailtest.Start(t)
	srv := newServer(t, DefaultSafety(), box.Account("work"), box.Account("home"))

	res := call(t, srv, "imap_list_mailboxes", map[string]any{})
	if !res.IsError || !strings.Contains(res.Text, "work, home") {
		t.Fatalf("при нескольких ящиках без account_id нужен понятный отказ: %s", res.Text)
	}
	if res := call(t, srv, "imap_list_mailboxes", map[string]any{"account_id": "home"}); res.IsError {
		t.Fatal(res.Text)
	}
	res = call(t, srv, "imap_get_message", map[string]any{"account_id": "home", "message_id": "imap:work:INBOX:1:1"})
	if !res.IsError || !strings.Contains(res.Text, "account_id") {
		t.Fatalf("id чужого ящика должен отклоняться: %s", res.Text)
	}
}

func TestFilePathAttachmentConfinedToUploadDir(t *testing.T) {
	box := mailtest.Start(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("можно"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "id_rsa")
	_ = os.WriteFile(secret, []byte("PRIVATE"), 0o600)

	srv := mcp.NewServer("test", "0")
	reg := NewRegistry(Config{Accounts: []mail.Account{box.Account("work")}, UploadDir: dir}, allowAll(), srv)
	RegisterAll(reg)

	send := func(path string) mcptest.Result {
		return call(t, srv, "smtp_send_message", map[string]any{"to": []string{"bob@example.com"}, "subject": "f",
			"body_text": "см.", "attachments": []map[string]any{{"file_path": path}}})
	}
	if res := send(secret); !res.IsError {
		t.Fatal("файл вне папки загрузок ушёл вложением")
	}
	if res := send(filepath.Join(dir, "..", filepath.Base(filepath.Dir(secret)), "id_rsa")); !res.IsError {
		t.Fatal("выход из папки через .. не остановлен")
	}
	if res := send(filepath.Join(dir, "ok.txt")); res.IsError {
		t.Fatalf("файл из папки загрузок должен уходить: %s", res.Text)
	}
	for _, m := range box.SentMessages() {
		if strings.Contains(string(m.Data), base64.StdEncoding.EncodeToString([]byte("PRIVATE"))) {
			t.Fatal("секретный файл оказался в письме")
		}
	}
}

func TestHTMLInTextFieldRejected(t *testing.T) {
	box := mailtest.Start(t)
	srv := newServer(t, allowAll(), box.Account("work"))
	res := call(t, srv, "smtp_send_message", map[string]any{"to": []string{"b@x.ru"}, "subject": "s",
		"body_text": "<html><body><p>Привет</p></body></html>"})
	if !res.IsError || !strings.Contains(res.Text, "body_html") {
		t.Fatalf("HTML в body_text должен отклоняться: %s", res.Text)
	}
}

func TestToolsHaveDescriptionsAndUniqueNames(t *testing.T) {
	srv := newServer(t, DefaultSafety())
	sess, err := mcptest.Start(srv)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	list, err := sess.Tools()
	if err != nil {
		t.Fatal(err)
	}
	// Имена из исходного mail-mcp: по ним ходят уже написанные промпты.
	for _, want := range []string{"list_all_accounts", "imap_search_messages", "imap_get_message",
		"smtp_send_message", "draft_send", "imap_search_and_delete", "mail_status", "mail_selftest"} {
		found := false
		for _, tl := range list {
			if tl.Name == want {
				found = true
			}
		}
		if !found {
			t.Errorf("нет инструмента %s", want)
		}
	}
	for _, tl := range list {
		if len(tl.Description) < 20 {
			t.Errorf("%s: описание слишком короткое для модели: %q", tl.Name, tl.Description)
		}
	}
}

func TestStatusShowsPermissions(t *testing.T) {
	box := mailtest.Start(t)
	s := DefaultSafety()
	s.Send = true
	srv := newServer(t, s, box.Account("work"))
	res := call(t, srv, "mail_status", map[string]any{})
	if !strings.Contains(res.Text, "чтение + отправка") || !strings.Contains(res.Text, "work") {
		t.Fatalf("статус: %s", res.Text)
	}
	res = call(t, srv, "mail_selftest", map[string]any{})
	if !strings.Contains(res.Text, "Всё работает") {
		t.Fatalf("самопроверка: %s", res.Text)
	}
}
