package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// protectedResourceMetadata — RFC 9728.
//
// С этого документа начинается всё подключение: клиент получает 401,
// читает отсюда адрес сервера авторизации и идёт туда.
//
// Поле resource должно совпадать с адресом, который пользователь ввёл
// в Claude, ВПЛОТЬ ДО СИМВОЛА. Расхождение в одном слэше — и клиент
// решит, что метаданные не от этого сервера, а сообщение об ошибке
// будет невнятным.
func (s *Server) protectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                                   s.cfg.ResourceURL,
		"authorization_servers":                      []string{s.cfg.Issuer},
		"scopes_supported":                           MailScopes,
		"bearer_methods_supported":                   []string{"header"},
		"resource_documentation":                     "https://github.com/MainAlexStark/email-mcp",
		"resource_name":                              "Email MCP",
		"tls_client_certificate_bound_access_tokens": false,
	})
}

// authorizationServerMetadata — RFC 8414.
//
// Клиент читает отсюда, куда слать запросы и что сервер умеет.
// code_challenge_methods_supported обязателен: без него совместимый
// клиент не станет начинать поток, потому что не сможет убедиться,
// что PKCE поддержан.
func (s *Server) authorizationServerMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                 s.cfg.Issuer,
		"authorization_endpoint": s.cfg.Issuer + "/oauth/authorize",
		"token_endpoint":         s.cfg.Issuer + "/oauth/token",
		"registration_endpoint":  s.cfg.Issuer + "/oauth/register",
		"revocation_endpoint":    s.cfg.Issuer + "/oauth/revoke",

		"scopes_supported":         append(append([]string(nil), MailScopes...), ScopeOfflineAccess),
		"response_types_supported": []string{"code"},
		"grant_types_supported":    []string{"authorization_code", "refresh_token"},

		// S256 и только он: plain небезопасен и в OAuth 2.1 запрещён.
		"code_challenge_methods_supported": []string{"S256"},

		// Клиенты Claude регистрируются как публичные и секретом
		// на token-эндпоинте не пользуются.
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},

		// RFC 8707: токен привязывается к конкретному ресурсу.
		"resource_indicators_supported": true,

		"revocation_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"service_documentation":                      "https://github.com/MainAlexStark/email-mcp",
	})
}

// WriteUnauthorized отдаёт 401 с указанием, где искать метаданные.
//
// Заголовок WWW-Authenticate именно на 401 — на 200 Claude его
// не читает, и подключение молча не состоится.
func (s *Server) WriteUnauthorized(w http.ResponseWriter, description string) {
	metadataURL := s.cfg.Issuer + "/.well-known/oauth-protected-resource"

	header := fmt.Sprintf(
		`Bearer realm="email-mcp", resource_metadata=%q, scope=%q`,
		metadataURL, strings.Join(MailScopes, " "))

	if description != "" {
		header += fmt.Sprintf(`, error="invalid_token", error_description=%q`, description)
	}

	w.Header().Set("WWW-Authenticate", header)
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error":             "invalid_token",
		"error_description": description,
	})
}

// WriteForbidden отдаёт 403: токен действителен, но прав не хватает.
//
// Отличать 403 от 401 важно: на 401 клиент побежит обновлять токен,
// и при нехватке прав это превратится в бесконечный цикл обновлений.
func (s *Server) WriteForbidden(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer error="insufficient_scope", scope=%q, error_description=%q`,
			ScopeSend, description))
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":             "insufficient_scope",
		"error_description": description,
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeOAuthError отдаёт ошибку в формате OAuth.
//
// Коды берутся из RFC 6749 буквально: Claude различает invalid_grant
// (надо заново пройти согласие) и остальные, и на свой код поведёт
// себя не так, как нужно.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]any{
		"error":             code,
		"error_description": description,
	})
}
