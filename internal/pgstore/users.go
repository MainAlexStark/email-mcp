package pgstore

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ErrEmailTaken — адрес уже зарегистрирован.
var ErrEmailTaken = errors.New("pgstore: адрес уже зарегистрирован")

// User — учётная запись.
type User struct {
	ID           int64
	Email        string
	PasswordHash string
	Plan         string
	Disabled     bool
	CreatedAt    time.Time
	LastLoginAt  *time.Time
}

// NormalizeEmail приводит адрес к виду, в котором он хранится и ищется.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// CreateUser заводит пользователя.
func (db *DB) CreateUser(ctx context.Context, email, passwordHash string) (User, error) {
	u := User{Email: NormalizeEmail(email), PasswordHash: passwordHash}
	err := db.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash) VALUES ($1, $2)
		RETURNING id, plan, created_at`,
		u.Email, passwordHash,
	).Scan(&u.ID, &u.Plan, &u.CreatedAt)
	if isUniqueViolation(err) {
		return User{}, ErrEmailTaken
	}
	return u, err
}

const userColumns = `id, email, password_hash, plan, disabled_at IS NOT NULL, created_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Plan, &u.Disabled, &u.CreatedAt, &u.LastLoginAt)
	return u, notFound(err)
}

// UserByEmail ищет пользователя по адресу.
func (db *DB) UserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(db.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(email) = $1`, NormalizeEmail(email)))
}

// UserByID ищет пользователя по номеру.
func (db *DB) UserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(db.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

// TouchLogin отмечает время входа.
func (db *DB) TouchLogin(ctx context.Context, userID int64) error {
	_, err := db.pool.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, userID)
	return err
}

// SetPassword меняет пароль и закрывает все сессии кабинета, кроме
// keepSession (хеш; пусто — закрыть все). Сменивший пароль из-за
// подозрения на взлом ждёт, что чужой браузер вылетит сразу.
func (db *DB) SetPassword(ctx context.Context, userID int64, passwordHash, keepSession string) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2 WHERE id = $1`, userID, passwordHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM web_sessions WHERE user_id = $1 AND token_hash <> $2`, userID, keepSession); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetDisabled блокирует или разблокирует пользователя. Блокировка
// сразу закрывает кабинет и все подключения: сессии и токены
// проверяются с оглядкой на disabled_at.
func (db *DB) SetDisabled(ctx context.Context, email string, disabled bool) error {
	q := `UPDATE users SET disabled_at = NULL WHERE lower(email) = $1`
	if disabled {
		q = `UPDATE users SET disabled_at = now() WHERE lower(email) = $1 AND disabled_at IS NULL`
	}
	tag, err := db.pool.Exec(ctx, q, NormalizeEmail(email))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, err := db.UserByEmail(ctx, email); err != nil {
			return err
		}
	}
	return nil
}

// DeleteUser удаляет пользователя со всем, что ему принадлежит.
func (db *DB) DeleteUser(ctx context.Context, userID int64) error {
	tag, err := db.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UserSummary — строка списка пользователей для администратора.
type UserSummary struct {
	User
	Mailboxes int
	Calls30d  int64
}

// ListUsers перечисляет пользователей, новые сверху.
func (db *DB) ListUsers(ctx context.Context) ([]UserSummary, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT u.id, u.email, u.password_hash, u.plan, u.disabled_at IS NOT NULL, u.created_at, u.last_login_at,
		       (SELECT count(*) FROM mailboxes m WHERE m.user_id = u.id)::int,
		       COALESCE((SELECT sum(calls) FROM usage_daily d
		                 WHERE d.user_id = u.id AND d.day > current_date - 30), 0)::bigint
		FROM users u ORDER BY u.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UserSummary
	for rows.Next() {
		var s UserSummary
		if err := rows.Scan(&s.ID, &s.Email, &s.PasswordHash, &s.Plan, &s.Disabled, &s.CreatedAt,
			&s.LastLoginAt, &s.Mailboxes, &s.Calls30d); err != nil {
			return nil, err
		}
		s.PasswordHash = ""
		out = append(out, s)
	}
	return out, rows.Err()
}

// --- Сессии кабинета ---

// WebSession — вход в кабинет из браузера.
type WebSession struct {
	UserID int64
	Email  string
	CSRF   string
}

// CreateWebSession сохраняет сессию (хеш cookie).
func (db *DB) CreateWebSession(ctx context.Context, tokenHash string, userID int64, csrf string, expires time.Time) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO web_sessions (token_hash, user_id, csrf, expires_at) VALUES ($1, $2, $3, $4)`,
		tokenHash, userID, csrf, expires)
	return err
}

// WebSession находит живую сессию незаблокированного пользователя.
func (db *DB) WebSession(ctx context.Context, tokenHash string) (WebSession, error) {
	var s WebSession
	err := db.pool.QueryRow(ctx, `
		SELECT u.id, u.email, s.csrf
		FROM web_sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > now() AND u.disabled_at IS NULL`,
		tokenHash).Scan(&s.UserID, &s.Email, &s.CSRF)
	return s, notFound(err)
}

// DeleteWebSession закрывает сессию (выход).
func (db *DB) DeleteWebSession(ctx context.Context, tokenHash string) error {
	_, err := db.pool.Exec(ctx, `DELETE FROM web_sessions WHERE token_hash = $1`, tokenHash)
	return err
}
