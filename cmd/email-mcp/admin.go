package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/MainAlexStark/email-mcp/internal/pgstore"
	"github.com/MainAlexStark/email-mcp/internal/secure"
)

// Команды администратора сервиса. Работают с той же базой, что и
// сервер (MAIL_DATABASE_URL), и запускаются рядом с ним:
//
//	docker compose exec email-mcp /email-mcp --users

func printSecretKey() {
	key, err := secure.GenerateSecretKey()
	if err != nil {
		fatal(err.Error())
	}
	fmt.Println(key)
	fmt.Fprintln(os.Stderr,
		"\nПоложите строку в MAIL_SECRET_KEY. Ею шифруются пароли почтовых ящиков:\n"+
			"потеряете — все ящики придётся подключать заново. Сохраните копию\n"+
			"отдельно от резервных копий базы.")
}

func adminDB() (*pgstore.DB, context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	url := os.Getenv("MAIL_DATABASE_URL")
	if url == "" {
		cancel()
		fatal("нужен MAIL_DATABASE_URL")
	}
	db, err := pgstore.Open(ctx, url)
	if err != nil {
		cancel()
		fatal(err.Error())
	}
	return db, ctx, cancel
}

func runMigrate() {
	db, ctx, cancel := adminDB()
	defer cancel()
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		fatal(err.Error())
	}
	fmt.Println("Миграции применены.")
}

func listUsers() {
	db, ctx, cancel := adminDB()
	defer cancel()
	defer db.Close()

	list, err := db.ListUsers(ctx)
	if err != nil {
		fatal(err.Error())
	}
	if len(list) == 0 {
		fmt.Println("Пользователей нет.")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tПОЧТА\tТАРИФ\tЯЩИКОВ\tВЫЗОВОВ 30Д\tЗАРЕГИСТРИРОВАН\tСТАТУС")
	for _, u := range list {
		status := "активен"
		if u.Disabled {
			status = "заблокирован"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%d\t%s\t%s\n",
			u.ID, u.Email, u.Plan, u.Mailboxes, u.Calls30d, u.CreatedAt.Format("02.01.2006"), status)
	}
	_ = tw.Flush()
}

func setDisabled(email string, disabled bool) {
	db, ctx, cancel := adminDB()
	defer cancel()
	defer db.Close()

	if err := db.SetDisabled(ctx, email, disabled); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			fatal("пользователь не найден: " + email)
		}
		fatal(err.Error())
	}
	if disabled {
		fmt.Println("Заблокирован. Кабинет, подключения Claude и токены перестали работать немедленно.")
	} else {
		fmt.Println("Разблокирован. Входить в кабинет можно; подключения, выданные до блокировки, снова работают.")
	}
}

// resetPassword задаёт пароль пользователю, который его забыл.
//
// Пароль читается со stdin, а не из аргумента: аргументы видны любому
// пользователю машины через ps и оседают в истории оболочки.
func resetPassword(email string) {
	fmt.Fprint(os.Stderr, "Новый пароль (от 8 символов): ")
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		fatal("пароль не прочитан")
	}
	hash, err := secure.HashPassword(strings.TrimSpace(sc.Text()))
	if err != nil {
		fatal(err.Error())
	}

	db, ctx, cancel := adminDB()
	defer cancel()
	defer db.Close()

	user, err := db.UserByEmail(ctx, email)
	if err != nil {
		fatal("пользователь не найден: " + email)
	}
	if err := db.SetPassword(ctx, user.ID, hash, ""); err != nil {
		fatal(err.Error())
	}
	fmt.Println("Пароль изменён, все сессии кабинета закрыты.")
}

// createInvites выпускает приглашения и печатает ссылки на регистрацию.
//
// Коды печатаются один раз: в базе только их хеш, и повторить их потом
// невозможно — как и с API-токенами.
func createInvites(n int, note string, ttl time.Duration) {
	if n > 100 {
		fatal("не больше 100 приглашений за раз")
	}
	db, ctx, cancel := adminDB()
	defer cancel()
	defer db.Close()

	var expires *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expires = &t
	}
	base := strings.TrimSuffix(os.Getenv("MAIL_PUBLIC_URL"), "/")
	for i := 0; i < n; i++ {
		code, err := secure.RandomToken()
		if err != nil {
			fatal(err.Error())
		}
		if _, err := db.CreateInvite(ctx, secure.HashToken(code), note, expires); err != nil {
			fatal(err.Error())
		}
		if base != "" {
			fmt.Printf("%s/signup?invite=%s\n", base, code)
		} else {
			fmt.Println(code)
		}
	}
	if expires != nil {
		fmt.Fprintf(os.Stderr, "\nДействуют до %s. Каждое — на одну регистрацию.\n", expires.Format("02.01.2006 15:04"))
	}
	if os.Getenv("MAIL_REGISTRATION") != "invite" {
		fmt.Fprintln(os.Stderr, "Внимание: MAIL_REGISTRATION не invite — приглашения сейчас не спрашиваются.")
	}
}

func listInvites() {
	db, ctx, cancel := adminDB()
	defer cancel()
	defer db.Close()

	list, err := db.Invites(ctx)
	if err != nil {
		fatal(err.Error())
	}
	if len(list) == 0 {
		fmt.Println("Приглашений нет.")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tПОМЕТКА\tВЫПУЩЕНО\tДО\tИСПОЛЬЗОВАНО")
	for _, i := range list {
		until := "бессрочно"
		if i.ExpiresAt != nil {
			until = i.ExpiresAt.Format("02.01.2006")
		}
		used := "—"
		if i.UsedAt != nil {
			used = i.UsedAt.Format("02.01.2006") + " " + i.UsedBy
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", i.ID, i.Note, i.CreatedAt.Format("02.01.2006"), until, used)
	}
	_ = tw.Flush()
}
