package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/MainAlexStark/email-mcp/internal/mcp"
	"github.com/MainAlexStark/email-mcp/mail"
)

// RegisterDiagnostics добавляет инструменты состояния и самопроверки.
func (r *Registry) RegisterDiagnostics() {
	r.AddCustom(mcp.Tool{
		Name: "mail_status",
		Description: "Состояние подключения: права (чтение, черновики, изменение, отправка), пороги защиты, ящики. " +
			"Вызовите первым, если непонятно, почему инструмент отказывается что-то делать.",
		InputSchema: schema(obj{}),
		Handler: func(ctx context.Context, _ json.RawMessage) (string, error) {
			s := r.safetyFor(ctx)
			var b strings.Builder
			fmt.Fprintf(&b, "Права этого подключения:  %s\n", s.Mode())
			if !s.Drafts || !s.Write || !s.Send {
				b.WriteString("                          (недостающие права: локально — MAIL_ALLOW_DRAFTS/WRITES/SEND,\n")
				b.WriteString("                           в сервисе — галочки на экране согласия при подключении)\n")
			}
			fmt.Fprintf(&b, "Писем за одну операцию:   %d\n", s.MaxItemsPerWrite)
			fmt.Fprintf(&b, "Получателей без confirm:  %d\n", s.MaxRecipients)
			fmt.Fprintf(&b, "Потолок ответа:           %d байт\n", s.MaxResponseBytes)
			fmt.Fprintf(&b, "Вложения сохраняются:     %s\n", describeFiles(r.cfg.Files))
			list, _ := r.accountsFor(ctx)
			fmt.Fprintf(&b, "\nЯщики (%d):\n", len(list))
			for _, acc := range list {
				send := "без отправки"
				if acc.SMTP.Configured() {
					send = "SMTP " + acc.SMTP.Host
				}
				fmt.Fprintf(&b, "  %-16s %-32s IMAP %s, %s\n", acc.ID, acc.Sender(), acc.IMAP.Host, send)
			}
			if len(list) == 0 {
				b.WriteString("  нет — " + ErrNoAccounts.Error() + "\n")
			}
			fmt.Fprintf(&b, "\nИнструментов зарегистрировано: %d\n", len(r.server.ToolNames()))
			b.WriteString("Проверить вход во все ящики: mail_selftest.")
			return b.String(), nil
		},
	})

	r.AddCustom(mcp.Tool{
		Name: "mail_selftest",
		Description: "Проверить все ящики подключения разом: вход по IMAP, список папок, вход по SMTP. " +
			"Параллельно, с таймаутом. Показывает, какой ящик и на каком шаге не пускает, и что с этим делать.",
		InputSchema: schema(obj{}),
		Handler: func(ctx context.Context, _ json.RawMessage) (string, error) {
			list, _ := r.accountsFor(ctx)
			if len(list) == 0 {
				return ErrNoAccounts.Error(), nil
			}
			lines := make([][]string, len(list))
			fails := make([]int, len(list))
			var wg sync.WaitGroup
			for i, acc := range list {
				wg.Add(1)
				go func(i int, acc mail.Account) {
					defer wg.Done()
					lines[i], fails[i] = r.probeAccount(ctx, acc)
				}(i, acc)
			}
			wg.Wait()

			var b strings.Builder
			b.WriteString("Проверка ящиков\n")
			total := 0
			for i, acc := range list {
				fmt.Fprintf(&b, "\n%s (%s)\n", acc.ID, acc.Sender())
				for _, l := range lines[i] {
					b.WriteString("  " + l + "\n")
				}
				total += fails[i]
			}
			if total == 0 {
				b.WriteString("\nВсё работает.")
			}
			return b.String(), nil
		},
	})
}

// probeAccount — три шага проверки одного ящика. Второе значение —
// сколько шагов не прошло.
func (r *Registry) probeAccount(ctx context.Context, acc mail.Account) ([]string, int) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	acc.Timeout = 30 * time.Second
	c := mail.New(acc, r.cfg.MailOptions...)

	var out []string
	fails := 0
	line := func(step string, start time.Time, err error) {
		if err == nil {
			out = append(out, fmt.Sprintf("OK      %-16s %s", step, time.Since(start).Round(time.Millisecond)))
			return
		}
		fails++
		out = append(out, fmt.Sprintf("ОШИБКА  %-16s %v", step, err))
		if h := mail.Hint(err); h != "" {
			out = append(out, "        "+h)
		}
	}

	start := time.Now()
	_, err := c.VerifyIMAP(ctx)
	line("IMAP вход", start, err)
	if err == nil {
		start = time.Now()
		boxes, err := c.ListMailboxes(ctx)
		line("папки", start, err)
		if err == nil {
			roles := map[string]string{}
			for _, mb := range boxes {
				if mb.Role != "" && roles[mb.Role] == "" {
					roles[mb.Role] = mb.Name
				}
			}
			for _, role := range []string{mail.RoleSent, mail.RoleDrafts, mail.RoleTrash} {
				if roles[role] == "" {
					out = append(out, fmt.Sprintf("ВНИМАНИЕ папка роли %q не найдена — инструменты, которым она нужна, не сработают", role))
				}
			}
		}
	}
	if acc.SMTP.Configured() {
		start = time.Now()
		_, err := c.VerifySMTP(ctx)
		line("SMTP вход", start, err)
	} else {
		out = append(out, "—       SMTP не настроен: отправка с этого ящика невозможна")
	}
	return out, fails
}
