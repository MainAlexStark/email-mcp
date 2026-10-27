package httpx

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBearerTokenFromHeader(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer abc123")

	if got := bearerToken(r); got != "abc123" {
		t.Errorf("токен из заголовка: %q", got)
	}
}

func TestBearerTokenIgnoresOtherSchemes(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	if got := bearerToken(r); got != "" {
		t.Errorf("схема Basic не должна приниматься за Bearer: %q", got)
	}
}

func TestTokenInURLNoLongerAccepted(t *testing.T) {
	// Спецификация MCP запрещает токен в строке запроса: адреса
	// оседают в журналах прокси и истории браузера. Проверяем, что
	// прежний способ действительно убран, а не остался «на всякий».
	secret := strings.Repeat("a", 64)
	r := httptest.NewRequest("POST", "/mcp/"+secret, nil)

	if got := bearerToken(r); got != "" {
		t.Errorf("токен из адреса не должен извлекаться, получено %q", got)
	}
}
