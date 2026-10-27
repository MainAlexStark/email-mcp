package oauth

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// registrationRequest — RFC 7591.
type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// handleRegister — динамическая регистрация клиента.
//
// Тело здесь JSON (RFC 7591), в отличие от token-эндпоинта, который
// принимает форму. Разные форматы у соседних эндпоинтов — известная
// ловушка: один общий парсер приведёт к 415 на одном из них.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "тело запроса не разобрано как JSON")
		return
	}

	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "не указан ни один redirect_uri")
		return
	}

	for _, uri := range req.RedirectURIs {
		if err := validateRedirectURI(uri); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}

	id, err := randomToken()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "не удалось выдать идентификатор")
		return
	}

	client := &Client{
		ID:           id,
		Name:         strings.TrimSpace(req.ClientName),
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    time.Now(),
	}
	if client.Name == "" {
		client.Name = "клиент без имени"
	}

	resp := map[string]any{
		"client_id":                  client.ID,
		"client_id_issued_at":        client.CreatedAt.Unix(),
		"client_name":                client.Name,
		"redirect_uris":              client.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      strings.Join(append(append([]string(nil), MailScopes...), ScopeOfflineAccess), " "),
	}

	// Секрет выдаём только тем, кто сам просит подтверждать себя им.
	// Клиенты Claude регистрируются публичными: секрет в приложении,
	// которое отдаётся пользователю, всё равно не секрет.
	if req.TokenEndpointAuthMethod == "client_secret_post" || req.TokenEndpointAuthMethod == "client_secret_basic" {
		secret, err := randomToken()
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "не удалось выдать секрет")
			return
		}
		client.SecretHash = hashToken(secret)
		resp["client_secret"] = secret
		resp["token_endpoint_auth_method"] = "client_secret_post"
	}

	if err := s.store.SaveClient(r.Context(), client); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "не удалось сохранить клиента")
		return
	}

	s.logger.Info("зарегистрирован клиент",
		"client_id", client.ID,
		"name", client.Name,
		"redirect_uris", client.RedirectURIs)

	writeJSON(w, http.StatusCreated, resp)
}

// validateRedirectURI проверяет адрес возврата.
//
// Требования спецификации: только https либо loopback. http на внешний
// адрес означал бы, что код авторизации поедет открытым текстом.
func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errConfig("redirect_uri не разобран: " + raw)
	}
	if u.Fragment != "" {
		return errConfig("redirect_uri не должен содержать фрагмент: " + raw)
	}

	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return errConfig("http разрешён только для loopback: " + raw)
	default:
		return errConfig("недопустимая схема redirect_uri: " + raw)
	}
}

// isLoopbackHost — адрес возврата на этой же машине.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// redirectURIAllowed сверяет запрошенный адрес с зарегистрированными.
//
// Сравнение точное — с одним исключением: у loopback игнорируется порт.
// Так требует RFC 8252, и без этого не работает Claude Code: он поднимает
// приёмник на случайном порту, а в метаданных объявляет адрес без порта.
// Ослабление узкое и касается только собственной машины пользователя.
func redirectURIAllowed(registered []string, requested string) bool {
	for _, reg := range registered {
		if reg == requested {
			return true
		}
		if loopbackEqualIgnoringPort(reg, requested) {
			return true
		}
	}
	return false
}

func loopbackEqualIgnoringPort(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	if ua.Scheme != "http" || ub.Scheme != "http" {
		return false
	}
	if !isLoopbackHost(ua.Hostname()) || !isLoopbackHost(ub.Hostname()) {
		return false
	}
	// Хост сравниваем без порта, путь — как есть: /callback и /other
	// это разные адреса даже на одной машине.
	return ua.Hostname() == ub.Hostname() && ua.Path == ub.Path
}
