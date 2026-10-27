package pgstore

import (
	"context"
	"errors"
	"time"
)

// ErrMailboxExists — ящик с таким именем у пользователя уже есть.
var ErrMailboxExists = errors.New("pgstore: ящик с таким именем уже подключён")

// Mailbox — подключённый почтовый ящик.
type Mailbox struct {
	ID           int64
	UserID       int64
	Name         string
	Email        string
	DisplayName  string
	IMAPHost     string
	IMAPPort     int
	IMAPSecurity string
	SMTPHost     string
	SMTPPort     int
	SMTPSecurity string
	Username     string
	PasswordEnc  []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
	CheckedAt    *time.Time
	CheckError   string
}

const mailboxColumns = `id, user_id, name, email, display_name, imap_host, imap_port, imap_security,
	smtp_host, smtp_port, smtp_security, username, password_enc, created_at, updated_at, checked_at, check_error`

func scanMailbox(row interface{ Scan(...any) error }) (Mailbox, error) {
	var m Mailbox
	err := row.Scan(&m.ID, &m.UserID, &m.Name, &m.Email, &m.DisplayName, &m.IMAPHost, &m.IMAPPort, &m.IMAPSecurity,
		&m.SMTPHost, &m.SMTPPort, &m.SMTPSecurity, &m.Username, &m.PasswordEnc,
		&m.CreatedAt, &m.UpdatedAt, &m.CheckedAt, &m.CheckError)
	return m, notFound(err)
}

// AddMailbox сохраняет ящик. CheckedAt — когда вход только что проверен.
func (db *DB) AddMailbox(ctx context.Context, m Mailbox) (Mailbox, error) {
	out, err := scanMailbox(db.pool.QueryRow(ctx, `
		INSERT INTO mailboxes (user_id, name, email, display_name, imap_host, imap_port, imap_security,
		                       smtp_host, smtp_port, smtp_security, username, password_enc, checked_at, check_error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING `+mailboxColumns,
		m.UserID, m.Name, m.Email, m.DisplayName, m.IMAPHost, m.IMAPPort, m.IMAPSecurity,
		m.SMTPHost, m.SMTPPort, m.SMTPSecurity, m.Username, m.PasswordEnc, m.CheckedAt, m.CheckError))
	if isUniqueViolation(err) {
		return Mailbox{}, ErrMailboxExists
	}
	return out, err
}

// UpdateMailbox меняет настройки и пароль ящика (после проверки входа).
func (db *DB) UpdateMailbox(ctx context.Context, m Mailbox) error {
	tag, err := db.pool.Exec(ctx, `
		UPDATE mailboxes SET email = $3, display_name = $4, imap_host = $5, imap_port = $6, imap_security = $7,
		       smtp_host = $8, smtp_port = $9, smtp_security = $10, username = $11, password_enc = $12,
		       updated_at = now(), checked_at = now(), check_error = ''
		WHERE id = $1 AND user_id = $2`,
		m.ID, m.UserID, m.Email, m.DisplayName, m.IMAPHost, m.IMAPPort, m.IMAPSecurity,
		m.SMTPHost, m.SMTPPort, m.SMTPSecurity, m.Username, m.PasswordEnc)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Mailboxes — ящики пользователя в порядке подключения.
func (db *DB) Mailboxes(ctx context.Context, userID int64) ([]Mailbox, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+mailboxColumns+` FROM mailboxes WHERE user_id = $1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Mailbox
	for rows.Next() {
		m, err := scanMailbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Mailbox возвращает ящик, только если он принадлежит пользователю.
func (db *DB) Mailbox(ctx context.Context, userID, mailboxID int64) (Mailbox, error) {
	return scanMailbox(db.pool.QueryRow(ctx,
		`SELECT `+mailboxColumns+` FROM mailboxes WHERE id = $1 AND user_id = $2`, mailboxID, userID))
}

// SetMailboxCheck записывает итог проверки входа ("" — вход работает).
func (db *DB) SetMailboxCheck(ctx context.Context, mailboxID int64, checkErr string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE mailboxes SET checked_at = now(), check_error = $2 WHERE id = $1`, mailboxID, checkErr)
	return err
}

// DeleteMailbox удаляет ящик. Подключения к нему умирают каскадом;
// подключения «ко всем ящикам» остаются, но этого ящика больше не видят.
func (db *DB) DeleteMailbox(ctx context.Context, userID, mailboxID int64) error {
	tag, err := db.pool.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1 AND user_id = $2`, mailboxID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
