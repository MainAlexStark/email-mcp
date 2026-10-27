// Package ui — общий вид страниц сервиса: стиль, заголовки безопасности,
// страница-сообщение. Страницы OAuth и кабинета выглядят одинаково, и
// пользователь не должен гадать, не подменили ли ему экран согласия.
package ui

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed style.css
var style string

// Style — CSS всех страниц. Встраивается в <style>: внешних файлов
// нет, и Content-Security-Policy может быть строгим.
var Style = template.CSS(style)

// NoCache выставляет заголовки HTML-страницы, которую нельзя кешировать
// и нельзя встраивать в чужие фреймы (защита от кликджекинга на
// кнопке «Разрешить»).
func NoCache(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self' https: http://localhost:* http://127.0.0.1:*; frame-ancestors 'none'; base-uri 'none'")
}

var messageTemplate = template.Must(template.New("message").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title><style>{{.Style}}</style></head>
<body><div class="card">
<h1>{{.Title}}</h1>
<p class="sub">{{.Message}}</p>
<p class="hint"><a href="/account">В кабинет</a></p>
</div></body></html>`))

// RenderMessage показывает страницу с заголовком и пояснением.
func RenderMessage(w http.ResponseWriter, status int, title, message string) {
	NoCache(w)
	w.WriteHeader(status)
	_ = messageTemplate.Execute(w, map[string]any{"Title": title, "Message": message, "Style": Style})
}
