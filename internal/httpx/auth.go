// Package httpx — сетевой транспорт MCP-сервера и его авторизация.
//
// Пока сервер работал по stdio, защита была неявной, но надёжной: его
// запускал сам пользователь на своей машине. В сети эта защита исчезает
// целиком, а в сервисе к тому же у каждого запроса свой хозяин и свои
// ящики. Поэтому здесь на входе отвечается сразу на три вопроса:
// кто пришёл, с какими правами и к каким ящикам.
package httpx

import (
	"context"
	"net/http"
	"strings"
)

// Grants — что разрешает предъявленный токен сверх чтения.
type Grants struct {
	Drafts bool
	Write  bool
	Send   bool
}

// GrantsFromScopes разбирает список прав токена. Понимает и OAuth-имена
// (mail:send), и короткие имена API-токенов (send).
func GrantsFromScopes(scopes []string) Grants {
	var g Grants
	for _, s := range scopes {
		switch strings.TrimPrefix(s, "mail:") {
		case "drafts":
			g.Drafts = true
		case "write":
			g.Write = true
		case "send":
			g.Send = true
		}
	}
	return g
}

func (g Grants) String() string {
	parts := []string{"read"}
	if g.Drafts {
		parts = append(parts, "drafts")
	}
	if g.Write {
		parts = append(parts, "write")
	}
	if g.Send {
		parts = append(parts, "send")
	}
	return strings.Join(parts, "+")
}

// Principal — чей это запрос.
type Principal struct {
	UserID int64
	// MailboxID 0 — все ящики пользователя.
	MailboxID int64
	Grants    Grants
	// Via — чем подтверждён: "oauth" или "api_token". Для журнала.
	Via string
}

// APITokenFunc проверяет персональный токен (автоматизация).
// ok=false — токен неизвестен.
type APITokenFunc func(ctx context.Context, token string) (p Principal, ok bool)

// APITokenPrefix — начало персональных токенов. По нему токен
// отличается от OAuth без похода в базу, а человек узнаёт его
// в конфиге скрипта.
const APITokenPrefix = "emc_"

// bearerToken достаёт токен из заголовка Authorization.
//
// Только заголовок: спецификация MCP требует именно его и запрещает
// строку запроса.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	after, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		// Регистр схемы по RFC 7235 не важен.
		if after, ok = strings.CutPrefix(h, "bearer "); !ok {
			return ""
		}
	}
	return strings.TrimSpace(after)
}
