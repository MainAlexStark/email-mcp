package pgstore

import (
	"context"
	"time"

	"github.com/MainAlexStark/email-mcp/internal/oauth"
)

// OAuth возвращает хранилище для сервера авторизации.
func (db *DB) OAuth() oauth.Storage { return oauthStore{db} }

type oauthStore struct{ db *DB }

var _ oauth.Storage = oauthStore{}

func mapErr(err error) error {
	if err == ErrNotFound {
		return oauth.ErrNotFound
	}
	return err
}

func (s oauthStore) SaveClient(ctx context.Context, c *oauth.Client) error {
	_, err := s.db.pool.Exec(ctx, `
		INSERT INTO oauth_clients (id, secret_hash, name, redirect_uris, created_at)
		VALUES ($1, $2, $3, $4, $5)`,
		c.ID, c.SecretHash, c.Name, c.RedirectURIs, c.CreatedAt)
	return err
}

func (s oauthStore) Client(ctx context.Context, id string) (*oauth.Client, error) {
	var c oauth.Client
	err := s.db.pool.QueryRow(ctx, `
		SELECT id, secret_hash, name, redirect_uris, created_at FROM oauth_clients WHERE id = $1`, id).
		Scan(&c.ID, &c.SecretHash, &c.Name, &c.RedirectURIs, &c.CreatedAt)
	if err != nil {
		return nil, mapErr(notFound(err))
	}
	return &c, nil
}

func (s oauthStore) SaveSession(ctx context.Context, l *oauth.LoginSession) error {
	_, err := s.db.pool.Exec(ctx, `
		INSERT INTO oauth_login_sessions
			(id, client_id, redirect_uri, state, scopes, resource, code_challenge, user_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		l.ID, l.ClientID, l.RedirectURI, l.State, l.Scopes, l.Resource, l.CodeChallenge, l.UserID, l.ExpiresAt)
	return err
}

const sessionColumns = `id, client_id, redirect_uri, state, scopes, resource, code_challenge, user_id, expires_at`

func scanSession(row interface{ Scan(...any) error }) (*oauth.LoginSession, error) {
	var l oauth.LoginSession
	err := row.Scan(&l.ID, &l.ClientID, &l.RedirectURI, &l.State, &l.Scopes, &l.Resource,
		&l.CodeChallenge, &l.UserID, &l.ExpiresAt)
	if err != nil {
		return nil, mapErr(notFound(err))
	}
	return &l, nil
}

func (s oauthStore) Session(ctx context.Context, id string) (*oauth.LoginSession, error) {
	return scanSession(s.db.pool.QueryRow(ctx,
		`SELECT `+sessionColumns+` FROM oauth_login_sessions WHERE id = $1 AND expires_at > now()`, id))
}

func (s oauthStore) TakeSession(ctx context.Context, id string) (*oauth.LoginSession, error) {
	return scanSession(s.db.pool.QueryRow(ctx,
		`DELETE FROM oauth_login_sessions WHERE id = $1 AND expires_at > now() RETURNING `+sessionColumns, id))
}

func (s oauthStore) SaveCode(ctx context.Context, c *oauth.AuthCode) error {
	_, err := s.db.pool.Exec(ctx, `
		INSERT INTO oauth_codes
			(code_hash, client_id, redirect_uri, scopes, resource, code_challenge, user_id, mailbox_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8::bigint, 0), $9)`,
		c.CodeHash, c.ClientID, c.RedirectURI, c.Scopes, c.Resource, c.CodeChallenge, c.UserID, c.MailboxID, c.ExpiresAt)
	return err
}

// TakeCode — DELETE … RETURNING: код извлекается и удаляется одним
// атомарным шагом, два параллельных обмена одного кода не пройдут оба.
func (s oauthStore) TakeCode(ctx context.Context, codeHash string) (*oauth.AuthCode, error) {
	var c oauth.AuthCode
	err := s.db.pool.QueryRow(ctx, `
		DELETE FROM oauth_codes WHERE code_hash = $1
		RETURNING code_hash, client_id, redirect_uri, scopes, resource, code_challenge, user_id, COALESCE(mailbox_id, 0), expires_at`,
		codeHash).Scan(&c.CodeHash, &c.ClientID, &c.RedirectURI, &c.Scopes, &c.Resource, &c.CodeChallenge,
		&c.UserID, &c.MailboxID, &c.ExpiresAt)
	if err != nil {
		return nil, mapErr(notFound(err))
	}
	if c.ExpiresAt.Before(nowFn()) {
		return nil, oauth.ErrNotFound
	}
	return &c, nil
}

func (s oauthStore) SaveTokens(ctx context.Context, at *oauth.Token, rt *oauth.RefreshToken) error {
	tx, err := s.db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO oauth_access_tokens
			(token_hash, grant_id, client_id, scopes, resource, user_id, mailbox_id, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7::bigint, 0), $8, $9)`,
		at.TokenHash, at.GrantID, at.ClientID, at.Scopes, at.Resource, at.UserID, at.MailboxID,
		at.IssuedAt, at.ExpiresAt); err != nil {
		return err
	}
	if rt != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO oauth_refresh_tokens
				(token_hash, grant_id, client_id, scopes, resource, user_id, mailbox_id, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7::bigint, 0), $8)`,
			rt.TokenHash, rt.GrantID, rt.ClientID, rt.Scopes, rt.Resource, rt.UserID, rt.MailboxID,
			rt.ExpiresAt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// AccessToken находит живой токен незаблокированного пользователя.
func (s oauthStore) AccessToken(ctx context.Context, tokenHash string) (*oauth.Token, error) {
	var t oauth.Token
	err := s.db.pool.QueryRow(ctx, `
		SELECT t.token_hash, t.grant_id, t.client_id, t.scopes, t.resource, t.user_id, COALESCE(t.mailbox_id, 0),
		       t.issued_at, t.expires_at
		FROM oauth_access_tokens t JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1 AND t.expires_at > now() AND u.disabled_at IS NULL`, tokenHash).
		Scan(&t.TokenHash, &t.GrantID, &t.ClientID, &t.Scopes, &t.Resource, &t.UserID, &t.MailboxID,
			&t.IssuedAt, &t.ExpiresAt)
	if err != nil {
		return nil, mapErr(notFound(err))
	}
	return &t, nil
}

func (s oauthStore) TakeRefreshToken(ctx context.Context, tokenHash string) (*oauth.RefreshToken, error) {
	var t oauth.RefreshToken
	err := s.db.pool.QueryRow(ctx, `
		DELETE FROM oauth_refresh_tokens WHERE token_hash = $1
		RETURNING token_hash, grant_id, client_id, scopes, resource, user_id, COALESCE(mailbox_id, 0), expires_at`, tokenHash).
		Scan(&t.TokenHash, &t.GrantID, &t.ClientID, &t.Scopes, &t.Resource, &t.UserID, &t.MailboxID, &t.ExpiresAt)
	if err != nil {
		return nil, mapErr(notFound(err))
	}
	if t.ExpiresAt.Before(nowFn()) {
		return nil, oauth.ErrNotFound
	}
	// Заблокированному пользователю обновление не выдаём.
	var disabled bool
	if err := s.db.pool.QueryRow(ctx,
		`SELECT disabled_at IS NOT NULL FROM users WHERE id = $1`, t.UserID).Scan(&disabled); err != nil || disabled {
		return nil, oauth.ErrNotFound
	}
	return &t, nil
}

func (s oauthStore) GrantIDByToken(ctx context.Context, tokenHash string) (string, bool) {
	var g string
	err := s.db.pool.QueryRow(ctx, `
		SELECT grant_id FROM oauth_access_tokens WHERE token_hash = $1
		UNION ALL
		SELECT grant_id FROM oauth_refresh_tokens WHERE token_hash = $1
		LIMIT 1`, tokenHash).Scan(&g)
	return g, err == nil
}

func (s oauthStore) RevokeGrant(ctx context.Context, grantID string) (int, error) {
	tx, err := s.db.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	a, err := tx.Exec(ctx, `DELETE FROM oauth_access_tokens WHERE grant_id = $1`, grantID)
	if err != nil {
		return 0, err
	}
	r, err := tx.Exec(ctx, `DELETE FROM oauth_refresh_tokens WHERE grant_id = $1`, grantID)
	if err != nil {
		return 0, err
	}
	return int(a.RowsAffected() + r.RowsAffected()), tx.Commit(ctx)
}

// nowFn — текущее время; переменная ради тестов.
var nowFn = time.Now
