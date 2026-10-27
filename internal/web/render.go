package web

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"

	"github.com/MainAlexStark/email-mcp/internal/ui"
)

//go:embed templates/*.html
var templateFS embed.FS

// pages — каждая страница собирается из общего каркаса и своего тела.
var pages = func() map[string]*template.Template {
	funcs := template.FuncMap{
		"style": func() template.CSS { return ui.Style },
		"has": func(list []string, s string) bool {
			for _, v := range list {
				if v == s {
					return true
				}
			}
			return false
		},
	}
	out := map[string]*template.Template{}
	for _, name := range []string{"landing", "signup", "login", "message", "account", "mailbox_form"} {
		out[name] = template.Must(template.New("layout.html").Funcs(funcs).
			ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html"))
	}
	return out
}()

// render рисует страницу. Сначала в буфер: ошибка шаблона посреди
// ответа оставила бы человеку половину страницы с кодом 200.
func (w *Web) render(rw http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := pages[name].Execute(&buf, data); err != nil {
		w.logger.Error("шаблон", "page", name, "err", err)
		ui.RenderMessage(rw, http.StatusInternalServerError, "Что-то сломалось", "Страница не собралась.")
		return
	}
	ui.NoCache(rw)
	rw.WriteHeader(status)
	_, _ = buf.WriteTo(rw)
}
