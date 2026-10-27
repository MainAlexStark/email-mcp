package pgstore_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MainAlexStark/email-mcp/internal/oauth"
	"github.com/MainAlexStark/email-mcp/internal/pgstore"
	"github.com/MainAlexStark/email-mcp/internal/pgstore/pgtest"
)

var ctx = context.Background()

func newUser(t *testing.T, db *pgstore.DB) pgstore.User {
	t.Helper()
	u, err := db.CreateUser(ctx, pgtest.Email("user"), "hash")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func newBox(t *testing.T, db *pgstore.DB, userID int64, name string) pgstore.Mailbox {
	t.Helper()
	m, err := db.AddMailbox(ctx, pgstore.Mailbox{
		UserID: userID, Name: name, Email: name + "@example.com",
		IMAPHost: "imap.example.com", IMAPPort: 993, IMAPSecurity: "tls",
		SMTPHost: "smtp.example.com", SMTPPort: 465, SMTPSecurity: "tls",
		Username: name + "@example.com", PasswordEnc: []byte{1, 2, 3, 0, 255},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMigrateIsIdempotent(t *testing.T) {
	db := pgtest.Open(t)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("повторная миграция: %v", err)
	}
}

func TestEmailIsCaseInsensitiveAndUnique(t *testing.T) {
	db := pgtest.Open(t)
	email := pgtest.Email("Case")
	u, err := db.CreateUser(ctx, strings.ToUpper(email), "h")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != strings.ToLower(email) {
		t.Errorf("адрес не нормализован: %q", u.Email)
	}
	if _, err := db.CreateUser(ctx, email, "h"); !errors.Is(err, pgstore.ErrEmailTaken) {
		t.Fatalf("повторная регистрация: %v", err)
	}
	got, err := db.UserByEmail(ctx, "  "+strings.ToUpper(email)+" ")
	if err != nil || got.ID != u.ID {
		t.Fatalf("поиск без учёта регистра: %v %+v", err, got)
	}
}

func TestMailboxesAreIsolatedBetweenUsers(t *testing.T) {
	db := pgtest.Open(t)
	alice, bob := newUser(t, db), newUser(t, db)
	m := newBox(t, db, alice.ID, "work")

	if _, err := db.Mailbox(ctx, bob.ID, m.ID); !errors.Is(err, pgstore.ErrNotFound) {
		t.Fatalf("чужой ящик виден: %v", err)
	}
	if err := db.DeleteMailbox(ctx, bob.ID, m.ID); !errors.Is(err, pgstore.ErrNotFound) {
		t.Fatalf("чужой ящик удалился: %v", err)
	}
	upd := m
	upd.UserID = bob.ID
	upd.IMAPHost = "evil.example"
	if err := db.UpdateMailbox(ctx, upd); !errors.Is(err, pgstore.ErrNotFound) {
		t.Fatalf("чужой ящик изменён: %v", err)
	}
	got, err := db.Mailbox(ctx, alice.ID, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.PasswordEnc) != string([]byte{1, 2, 3, 0, 255}) || got.IMAPHost != "imap.example.com" {
		t.Errorf("запись исказилась: %+v", got)
	}
	// То же имя у другого пользователя — законно.
	newBox(t, db, bob.ID, "work")
	if _, err := db.AddMailbox(ctx, pgstore.Mailbox{UserID: alice.ID, Name: "WORK", Email: "x@y.z",
		IMAPHost: "h", IMAPPort: 1, IMAPSecurity: "tls", Username: "u", PasswordEnc: []byte{1}}); !errors.Is(err, pgstore.ErrMailboxExists) {
		t.Fatalf("дубль имени ящика (без учёта регистра): %v", err)
	}
}

func TestInviteIsSingleUse(t *testing.T) {
	db := pgtest.Open(t)
	code := pgtest.Email("invite")
	if _, err := db.CreateInvite(ctx, code, "для Пети", nil); err != nil {
		t.Fatal(err)
	}
	u, err := db.CreateUserWithInvite(ctx, pgtest.Email("petya"), "h", code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUserWithInvite(ctx, pgtest.Email("vasya"), "h", code); !errors.Is(err, pgstore.ErrInviteInvalid) {
		t.Fatalf("второе использование приглашения: %v", err)
	}
	// Занятый адрес не сжигает приглашение.
	code2 := pgtest.Email("invite2")
	_, _ = db.CreateInvite(ctx, code2, "", nil)
	if _, err := db.CreateUserWithInvite(ctx, u.Email, "h", code2); !errors.Is(err, pgstore.ErrEmailTaken) {
		t.Fatalf("занятый адрес: %v", err)
	}
	if _, err := db.CreateUserWithInvite(ctx, pgtest.Email("kolya"), "h", code2); err != nil {
		t.Fatalf("приглашение сгорело на неудачной регистрации: %v", err)
	}
	// Истёкшее не принимается.
	code3 := pgtest.Email("invite3")
	past := time.Now().Add(-time.Hour)
	_, _ = db.CreateInvite(ctx, code3, "", &past)
	if _, err := db.CreateUserWithInvite(ctx, pgtest.Email("late"), "h", code3); !errors.Is(err, pgstore.ErrInviteInvalid) {
		t.Fatalf("истёкшее приглашение: %v", err)
	}
	list, err := db.Invites(ctx)
	if err != nil || len(list) == 0 {
		t.Fatalf("список приглашений: %v", err)
	}
}

func issue(t *testing.T, st oauth.Storage, userID, mailboxID int64, hash, grant string, withRefresh bool, clientID ...string) {
	t.Helper()
	now := time.Now()
	cid := "c1"
	if len(clientID) > 0 {
		cid = clientID[0]
	}
	at := &oauth.Token{TokenHash: hash, ClientID: cid, Scopes: []string{oauth.ScopeRead},
		Resource: "https://x/mcp", IssuedAt: now, ExpiresAt: now.Add(time.Hour), GrantID: grant,
		Subject: oauth.Subject{UserID: userID, MailboxID: mailboxID}}
	var rt *oauth.RefreshToken
	if withRefresh {
		rt = &oauth.RefreshToken{TokenHash: "r-" + hash, ClientID: cid, Scopes: at.Scopes,
			Resource: at.Resource, ExpiresAt: now.Add(24 * time.Hour), GrantID: grant, Subject: at.Subject}
	}
	if err := st.SaveTokens(ctx, at, rt); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthStorageRoundTrip(t *testing.T) {
	db := pgtest.Open(t)
	st := db.OAuth()
	u := newUser(t, db)
	s := newBox(t, db, u.ID, "box222")

	client := &oauth.Client{ID: pgtest.Email("client"), Name: "Claude",
		RedirectURIs: []string{"https://claude.ai/cb", "http://localhost:1/cb"}, CreatedAt: time.Now()}
	if err := st.SaveClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	got, err := st.Client(ctx, client.ID)
	if err != nil || len(got.RedirectURIs) != 2 || got.RedirectURIs[1] != "http://localhost:1/cb" {
		t.Fatalf("клиент: %v %+v", err, got)
	}
	if _, err := st.Client(ctx, "нет-такого"); !errors.Is(err, oauth.ErrNotFound) {
		t.Fatalf("неизвестный клиент: %v", err)
	}

	sess := &oauth.LoginSession{ID: "sess-" + client.ID, ClientID: client.ID, RedirectURI: "https://claude.ai/cb",
		State: "st", Scopes: []string{"mail:read", "offline_access"}, Resource: "https://x/mcp",
		CodeChallenge: "ch", UserID: u.ID, ExpiresAt: time.Now().Add(time.Minute)}
	if err := st.SaveSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Session(ctx, sess.ID); err != nil || got.UserID != u.ID || len(got.Scopes) != 2 {
		t.Fatalf("сессия: %v %+v", err, got)
	}
	if _, err := st.TakeSession(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TakeSession(ctx, sess.ID); !errors.Is(err, oauth.ErrNotFound) {
		t.Fatal("сессия согласия должна быть одноразовой")
	}

	code := &oauth.AuthCode{CodeHash: "code-" + client.ID, ClientID: client.ID, RedirectURI: "https://claude.ai/cb",
		Scopes: []string{"mail:read"}, Resource: "https://x/mcp", CodeChallenge: "ch",
		ExpiresAt: time.Now().Add(time.Minute), Subject: oauth.Subject{UserID: u.ID, MailboxID: s.ID}}
	if err := st.SaveCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	gotCode, err := st.TakeCode(ctx, code.CodeHash)
	if err != nil || gotCode.MailboxID != s.ID || gotCode.UserID != u.ID {
		t.Fatalf("код: %v %+v", err, gotCode)
	}
	if _, err := st.TakeCode(ctx, code.CodeHash); !errors.Is(err, oauth.ErrNotFound) {
		t.Fatal("код должен быть одноразовым")
	}

	issue(t, st, u.ID, s.ID, "a-"+client.ID, "g-"+client.ID, true, client.ID)
	tok, err := st.AccessToken(ctx, "a-"+client.ID)
	if err != nil || tok.MailboxID != s.ID || tok.Scopes[0] != oauth.ScopeRead {
		t.Fatalf("access: %v %+v", err, tok)
	}
	if g, ok := st.GrantIDByToken(ctx, "r-a-"+client.ID); !ok || g != "g-"+client.ID {
		t.Fatalf("выдача по refresh: %q %v", g, ok)
	}

	grants, err := db.UserGrants(ctx, u.ID)
	if err != nil || len(grants) != 1 || grants[0].ClientName != "Claude" || grants[0].MailboxName != s.Name {
		t.Fatalf("подключения: %v %+v", err, grants)
	}

	rt, err := st.TakeRefreshToken(ctx, "r-a-"+client.ID)
	if err != nil || rt.MailboxID != s.ID {
		t.Fatalf("refresh: %v %+v", err, rt)
	}
	if _, err := st.TakeRefreshToken(ctx, "r-a-"+client.ID); !errors.Is(err, oauth.ErrNotFound) {
		t.Fatal("refresh должен ротироваться")
	}
	n, err := st.RevokeGrant(ctx, "g-"+client.ID)
	if err != nil || n != 1 {
		t.Fatalf("отзыв: %d %v", n, err)
	}
	if _, err := st.AccessToken(ctx, "a-"+client.ID); !errors.Is(err, oauth.ErrNotFound) {
		t.Fatal("отозванный токен жив")
	}
}

func TestDeletingMailboxKillsItsTokens(t *testing.T) {
	db := pgtest.Open(t)
	st := db.OAuth()
	u := newUser(t, db)
	s := newBox(t, db, u.ID, "box333")
	h := pgtest.Email("tok")
	issue(t, st, u.ID, s.ID, h, "g-"+h, true)
	if _, err := db.CreateAPIToken(ctx, u.ID, s.ID, "скрипт", "api-"+h, []string{"read"}); err != nil {
		t.Fatal(err)
	}

	// Подключение «ко всем ящикам» удаление одного ящика пережить должно.
	all := pgtest.Email("all")
	issue(t, st, u.ID, 0, all, "g-"+all, false)

	if err := db.DeleteMailbox(ctx, u.ID, s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AccessToken(ctx, h); !errors.Is(err, oauth.ErrNotFound) {
		t.Fatal("токен удалённого ящика продолжает работать")
	}
	if _, ok := st.GrantIDByToken(ctx, "r-"+h); ok {
		t.Fatal("refresh удалённого ящика остался")
	}
	if _, err := db.APITokenByHash(ctx, "api-"+h); !errors.Is(err, pgstore.ErrNotFound) {
		t.Fatal("API-токен удалённого ящика остался")
	}
	if tok, err := st.AccessToken(ctx, all); err != nil || tok.MailboxID != 0 {
		t.Fatalf("подключение ко всем ящикам не должно умирать вместе с одним: %v", err)
	}
}

func TestDisabledUserLosesAccessImmediately(t *testing.T) {
	db := pgtest.Open(t)
	st := db.OAuth()
	u := newUser(t, db)
	s := newBox(t, db, u.ID, "box444")
	h := pgtest.Email("dis")
	issue(t, st, u.ID, s.ID, h, "g-"+h, true)
	if _, err := db.CreateAPIToken(ctx, u.ID, s.ID, "скрипт", "api-"+h, []string{"read"}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateWebSession(ctx, "web-"+h, u.ID, "csrf", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := db.SetDisabled(ctx, u.Email, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AccessToken(ctx, h); err == nil {
		t.Error("access заблокированного работает")
	}
	if _, err := st.TakeRefreshToken(ctx, "r-"+h); err == nil {
		t.Error("refresh заблокированного работает")
	}
	if _, err := db.APITokenByHash(ctx, "api-"+h); err == nil {
		t.Error("API-токен заблокированного работает")
	}
	if _, err := db.WebSession(ctx, "web-"+h); err == nil {
		t.Error("сессия кабинета заблокированного работает")
	}
	if err := db.SetDisabled(ctx, "нет-такого@example.com", true); !errors.Is(err, pgstore.ErrNotFound) {
		t.Errorf("блокировка несуществующего: %v", err)
	}
}

func TestAPITokenCannotTargetForeignMailbox(t *testing.T) {
	db := pgtest.Open(t)
	alice, bob := newUser(t, db), newUser(t, db)
	bobBox := newBox(t, db, bob.ID, "bob")
	if _, err := db.CreateAPIToken(ctx, alice.ID, bobBox.ID, "x", pgtest.Email("h"), []string{"read"}); !errors.Is(err, pgstore.ErrNotFound) {
		t.Fatalf("токен к чужому ящику создан: %v", err)
	}

	aliceBox := newBox(t, db, alice.ID, "alice")
	h := pgtest.Email("api")
	id, err := db.CreateAPIToken(ctx, alice.ID, aliceBox.ID, "Отчёты", h, []string{"read", "send"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := db.APITokenByHash(ctx, h)
	if err != nil || tok.MailboxID != aliceBox.ID || len(tok.Scopes) != 2 {
		t.Fatalf("токен: %v %+v", err, tok)
	}
	hAll := pgtest.Email("api-all")
	if _, err := db.CreateAPIToken(ctx, alice.ID, 0, "Все", hAll, []string{"read"}); err != nil {
		t.Fatal(err)
	}
	list, _ := db.APITokens(ctx, alice.ID)
	if len(list) != 2 || list[0].LastUsedAt == nil || list[0].MailboxName != aliceBox.Name || list[1].MailboxID != 0 {
		t.Fatalf("список токенов: %+v", list)
	}
	if err := db.DeleteAPIToken(ctx, bob.ID, id); !errors.Is(err, pgstore.ErrNotFound) {
		t.Fatal("чужой токен отозван")
	}
}

func TestUsageAggregatesPerDay(t *testing.T) {
	db := pgtest.Open(t)
	u := newUser(t, db)
	for i := 0; i < 3; i++ {
		if err := db.RecordUsage(ctx, u.ID, 1, "imap_search_messages", i == 2); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.RecordUsage(ctx, u.ID, 1, "mail_status", false)
	n, err := db.UsageSince(ctx, u.ID, 30)
	if err != nil || n != 4 {
		t.Fatalf("вызовов %d, %v", n, err)
	}
}

func TestPasswordChangeClosesOtherSessions(t *testing.T) {
	db := pgtest.Open(t)
	u := newUser(t, db)
	exp := time.Now().Add(time.Hour)
	_ = db.CreateWebSession(ctx, "keep-"+u.Email, u.ID, "c", exp)
	_ = db.CreateWebSession(ctx, "drop-"+u.Email, u.ID, "c", exp)

	if err := db.SetPassword(ctx, u.ID, "new-hash", "keep-"+u.Email); err != nil {
		t.Fatal(err)
	}
	if _, err := db.WebSession(ctx, "keep-"+u.Email); err != nil {
		t.Error("текущая сессия должна остаться")
	}
	if _, err := db.WebSession(ctx, "drop-"+u.Email); err == nil {
		t.Error("остальные сессии должны закрыться")
	}
}

func TestDeleteUserRemovesEverything(t *testing.T) {
	db := pgtest.Open(t)
	u := newUser(t, db)
	s := newBox(t, db, u.ID, "box666")
	h := pgtest.Email("del")
	issue(t, db.OAuth(), u.ID, s.ID, h, "g-"+h, false)

	if err := db.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Mailbox(ctx, u.ID, s.ID); !errors.Is(err, pgstore.ErrNotFound) {
		t.Error("ящик пережил удаление пользователя")
	}
	if _, err := db.OAuth().AccessToken(ctx, h); err == nil {
		t.Error("токен пережил удаление пользователя")
	}
}

func TestCleanupRemovesExpired(t *testing.T) {
	db := pgtest.Open(t)
	u := newUser(t, db)
	h := pgtest.Email("old")
	_ = db.CreateWebSession(ctx, h, u.ID, "c", time.Now().Add(-time.Minute))
	if err := db.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.WebSession(ctx, h); err == nil {
		t.Error("истёкшая сессия жива")
	}
}
