package oauth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/MainAlexStark/email-mcp/internal/secure"
)

// Storage — хранилище клиентов, кодов и токенов.
//
// Токены непрозрачные (случайные строки), а не подписанные JWT.
// Подписанный токен нельзя отозвать до истечения срока, не заводя
// отдельный список отозванных, — а возможность отозвать доступ и есть
// главная причина, по которой здесь вообще OAuth.
//
// Хранилище получает не сами секреты, а их SHA-256: хеширует сервер
// авторизации. Утечка базы тогда не даёт доступа ни к одному ящику.
//
// Рабочая реализация — PostgreSQL (internal/pgstore). MemoryStore ниже —
// для тестов.
type Storage interface {
	SaveClient(ctx context.Context, c *Client) error
	Client(ctx context.Context, id string) (*Client, error)

	SaveSession(ctx context.Context, s *LoginSession) error
	// Session читает незавершённый вход, не удаляя его.
	Session(ctx context.Context, id string) (*LoginSession, error)
	// TakeSession извлекает вход и удаляет его: форма одноразовая.
	TakeSession(ctx context.Context, id string) (*LoginSession, error)

	SaveCode(ctx context.Context, c *AuthCode) error
	// TakeCode извлекает код и удаляет его: повторное использование —
	// признак перехвата.
	TakeCode(ctx context.Context, codeHash string) (*AuthCode, error)

	// SaveTokens сохраняет пару одной выдачи; rt может быть nil.
	SaveTokens(ctx context.Context, at *Token, rt *RefreshToken) error
	AccessToken(ctx context.Context, tokenHash string) (*Token, error)
	// TakeRefreshToken извлекает refresh и удаляет его (ротация).
	TakeRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	// GrantIDByToken находит выдачу по хешу любого из её токенов.
	GrantIDByToken(ctx context.Context, tokenHash string) (string, bool)
	// RevokeGrant удаляет выдачу целиком — и access, и refresh.
	RevokeGrant(ctx context.Context, grantID string) (int, error)
}

// Client — зарегистрированный OAuth-клиент.
type Client struct {
	ID           string    `json:"client_id"`
	SecretHash   string    `json:"client_secret_hash,omitempty"`
	Name         string    `json:"client_name"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
}

// Subject — на чьё имя и к каким ящикам выдан доступ.
//
// MailboxID 0 — ко всем ящикам пользователя, включая подключённые
// позже: так устроена почтовая программа, и так ждут люди с рабочим
// и личным ящиком. Конкретный ящик выбирают, когда подключают чужое
// или недоверенное приложение: тогда остальные ящики ему не видны
// вовсе, а не просто «не трогаются по просьбе». Выбор делает человек
// на экране согласия, и дальше он зашит в токен.
type Subject struct {
	UserID    int64 `json:"user_id"`
	MailboxID int64 `json:"mailbox_id"`
}

// AuthCode — выданный код авторизации.
type AuthCode struct {
	CodeHash      string    `json:"code_hash"`
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	Scopes        []string  `json:"scopes"`
	Resource      string    `json:"resource"`
	CodeChallenge string    `json:"code_challenge"`
	ExpiresAt     time.Time `json:"expires_at"`
	Subject
}

// Token — выданный access-токен.
type Token struct {
	TokenHash string    `json:"token_hash"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	Resource  string    `json:"resource"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`

	// GrantID связывает access и refresh одной выдачи: отзыв одного
	// должен убивать всю пару, иначе отозванный доступ воскресает
	// первым же обновлением.
	GrantID string `json:"grant_id"`
	Subject
}

// RefreshToken — токен обновления.
type RefreshToken struct {
	TokenHash string    `json:"token_hash"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	Resource  string    `json:"resource"`
	ExpiresAt time.Time `json:"expires_at"`
	GrantID   string    `json:"grant_id"`
	Subject
}

// LoginSession — незавершённый вход: пользователь открыл форму
// согласия, но ещё не подтвердил. UserID — кто её открыл: подтвердить
// может только он же.
type LoginSession struct {
	ID            string    `json:"id"`
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	State         string    `json:"state"`
	Scopes        []string  `json:"scopes"`
	Resource      string    `json:"resource"`
	CodeChallenge string    `json:"code_challenge"`
	UserID        int64     `json:"user_id"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// ErrNotFound — записи нет либо она истекла.
var ErrNotFound = errors.New("oauth: запись не найдена")

// MemoryStore — хранилище в памяти, для тестов.
type MemoryStore struct {
	mu            sync.Mutex
	clients       map[string]*Client
	codes         map[string]*AuthCode
	accessTokens  map[string]*Token
	refreshTokens map[string]*RefreshToken
	sessions      map[string]*LoginSession
}

// NewMemoryStore создаёт пустое хранилище в памяти.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients:       map[string]*Client{},
		codes:         map[string]*AuthCode{},
		accessTokens:  map[string]*Token{},
		refreshTokens: map[string]*RefreshToken{},
		sessions:      map[string]*LoginSession{},
	}
}

func (s *MemoryStore) SaveClient(_ context.Context, c *Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
	return nil
}

func (s *MemoryStore) Client(_ context.Context, id string) (*Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return nil, ErrNotFound
	}
	return c, nil
}

func (s *MemoryStore) SaveSession(_ context.Context, sess *LoginSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return nil
}

func (s *MemoryStore) Session(_ context.Context, id string) (*LoginSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil, ErrNotFound
	}
	return sess, nil
}

func (s *MemoryStore) TakeSession(_ context.Context, id string) (*LoginSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	delete(s.sessions, id)
	if time.Now().After(sess.ExpiresAt) {
		return nil, ErrNotFound
	}
	return sess, nil
}

func (s *MemoryStore) SaveCode(_ context.Context, c *AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[c.CodeHash] = c
	return nil
}

func (s *MemoryStore) TakeCode(_ context.Context, h string) (*AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[h]
	if !ok {
		return nil, ErrNotFound
	}
	delete(s.codes, h)
	if time.Now().After(c.ExpiresAt) {
		return nil, ErrNotFound
	}
	return c, nil
}

func (s *MemoryStore) SaveTokens(_ context.Context, at *Token, rt *RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTokens[at.TokenHash] = at
	if rt != nil {
		s.refreshTokens[rt.TokenHash] = rt
	}
	return nil
}

func (s *MemoryStore) AccessToken(_ context.Context, h string) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.accessTokens[h]
	if !ok || time.Now().After(t.ExpiresAt) {
		return nil, ErrNotFound
	}
	return t, nil
}

func (s *MemoryStore) TakeRefreshToken(_ context.Context, h string) (*RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refreshTokens[h]
	if !ok {
		return nil, ErrNotFound
	}
	delete(s.refreshTokens, h)
	if time.Now().After(rt.ExpiresAt) {
		return nil, ErrNotFound
	}
	return rt, nil
}

func (s *MemoryStore) GrantIDByToken(_ context.Context, h string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.accessTokens[h]; ok {
		return t.GrantID, true
	}
	if rt, ok := s.refreshTokens[h]; ok {
		return rt.GrantID, true
	}
	return "", false
}

func (s *MemoryStore) RevokeGrant(_ context.Context, grantID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for h, t := range s.accessTokens {
		if t.GrantID == grantID {
			delete(s.accessTokens, h)
			n++
		}
	}
	for h, rt := range s.refreshTokens {
		if rt.GrantID == grantID {
			delete(s.refreshTokens, h)
			n++
		}
	}
	return n, nil
}

// hashToken хеширует секрет для хранения.
func hashToken(token string) string { return secure.HashToken(token) }

// randomToken выдаёт криптостойкую случайную строку.
func randomToken() (string, error) { return secure.RandomToken() }
