package pgstore

import (
	"context"
	"errors"
	"time"
)

// ErrInviteInvalid — приглашения нет, оно использовано или истекло.
// Три случая намеренно не различаются: иначе форма регистрации
// подсказывала бы, какие коды когда-то существовали.
var ErrInviteInvalid = errors.New("pgstore: приглашение недействительно")

// Invite — приглашение (без самого кода: в базе только хеш).
type Invite struct {
	ID        int64
	Note      string
	CreatedAt time.Time
	ExpiresAt *time.Time
	UsedAt    *time.Time
	UsedBy    string
}

// CreateInvite сохраняет хеш нового приглашения.
func (db *DB) CreateInvite(ctx context.Context, codeHash, note string, expires *time.Time) (int64, error) {
	var id int64
	err := db.pool.QueryRow(ctx,
		`INSERT INTO invites (code_hash, note, expires_at) VALUES ($1, $2, $3) RETURNING id`,
		codeHash, note, expires).Scan(&id)
	return id, err
}

// Invites — все приглашения, новые сверху.
func (db *DB) Invites(ctx context.Context) ([]Invite, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT i.id, i.note, i.created_at, i.expires_at, i.used_at, COALESCE(u.email, '')
		FROM invites i LEFT JOIN users u ON u.id = i.used_by
		ORDER BY i.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var i Invite
		if err := rows.Scan(&i.ID, &i.Note, &i.CreatedAt, &i.ExpiresAt, &i.UsedAt, &i.UsedBy); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// CreateUserWithInvite заводит пользователя и гасит приглашение одной
// транзакцией: два человека с одним кодом не зарегистрируются оба,
// а неудачная регистрация (адрес занят) не сжигает код.
func (db *DB) CreateUserWithInvite(ctx context.Context, email, passwordHash, codeHash string) (User, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var inviteID int64
	err = tx.QueryRow(ctx, `
		SELECT id FROM invites
		WHERE code_hash = $1 AND used_at IS NULL AND (expires_at IS NULL OR expires_at > now())
		FOR UPDATE`, codeHash).Scan(&inviteID)
	if err != nil {
		if errors.Is(notFound(err), ErrNotFound) {
			return User{}, ErrInviteInvalid
		}
		return User{}, err
	}

	u := User{Email: NormalizeEmail(email), PasswordHash: passwordHash}
	err = tx.QueryRow(ctx, `
		INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, plan, created_at`,
		u.Email, passwordHash).Scan(&u.ID, &u.Plan, &u.CreatedAt)
	if isUniqueViolation(err) {
		return User{}, ErrEmailTaken
	}
	if err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE invites SET used_at = now(), used_by = $2 WHERE id = $1`, inviteID, u.ID); err != nil {
		return User{}, err
	}
	return u, tx.Commit(ctx)
}

// RevokeInvite удаляет неиспользованное приглашение.
func (db *DB) RevokeInvite(ctx context.Context, id int64) error {
	tag, err := db.pool.Exec(ctx, `DELETE FROM invites WHERE id = $1 AND used_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
