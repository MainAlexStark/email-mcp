// Package pgstore — хранилище сервиса в PostgreSQL.
//
// Здесь всё состояние, которое раньше жило в oauth.json и в окружении
// процесса: пользователи, их почтовые ящики (пароли зашифрованы), вход
// в кабинет, приглашения, OAuth-подключения, персональные токены и учёт
// вызовов.
//
// Пакет ничего не знает про HTTP и шифрование: пароли ящиков он
// получает и отдаёт уже зашифрованными, токены — уже хешированными.
package pgstore

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrNotFound — записи нет, она истекла или принадлежит другому
// пользователю. Последние два случая намеренно не отличаются: ответ
// «такой ящик есть, но не ваш» — уже утечка.
var ErrNotFound = errors.New("pgstore: не найдено")

// DB — подключение к базе.
type DB struct {
	pool *pgxpool.Pool
}

// Open подключается к базе и проверяет связь.
func Open(ctx context.Context, url string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("адрес базы (MAIL_DATABASE_URL): %w", err)
	}
	if cfg.MaxConns < 10 {
		cfg.MaxConns = 10
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("база не отвечает: %w", err)
	}
	return &DB{pool: pool}, nil
}

// Close закрывает пул.
func (db *DB) Close() { db.pool.Close() }

// Ping проверяет связь с базой.
func (db *DB) Ping(ctx context.Context) error { return db.pool.Ping(ctx) }

// Migrate применяет недостающие миграции.
//
// Каждая миграция — в своей транзакции под advisory-блокировкой: два
// процесса, стартующие одновременно (обновление с откатом), не должны
// применить одну миграцию дважды.
func (db *DB) Migrate(ctx context.Context) error {
	if _, err := db.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    text        PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("миграции: %w", err)
	}

	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)

	for _, name := range names {
		version := strings.TrimSuffix(strings.TrimPrefix(name, "migrations/"), ".sql")
		if err := db.applyMigration(ctx, name, version); err != nil {
			return fmt.Errorf("миграция %s: %w", version, err)
		}
	}
	return nil
}

func (db *DB) applyMigration(ctx context.Context, file, version string) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Число — произвольная константа сервиса: блокировка общая для всех
	// его экземпляров и не пересекается с чужими.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(81570002)`); err != nil {
		return err
	}

	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version,
	).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}

	sql, err := migrations.ReadFile(file)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, string(sql)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Cleanup удаляет истёкшие записи: сессии, коды, токены.
func (db *DB) Cleanup(ctx context.Context) error {
	for _, q := range []string{
		`DELETE FROM web_sessions WHERE expires_at < now()`,
		`DELETE FROM oauth_login_sessions WHERE expires_at < now()`,
		`DELETE FROM oauth_codes WHERE expires_at < now()`,
		`DELETE FROM oauth_access_tokens WHERE expires_at < now()`,
		`DELETE FROM oauth_refresh_tokens WHERE expires_at < now()`,
		`DELETE FROM invites WHERE used_at IS NULL AND expires_at < now()`,
		// Клиенты, зарегистрированные и ни разу не доведённые до токена
		// за сутки. Регистрация открыта (так требует MCP), и без этой
		// чистки таблицу можно раздувать бесконечно.
		`DELETE FROM oauth_clients c WHERE c.created_at < now() - interval '1 day'
		   AND NOT EXISTS (SELECT 1 FROM oauth_access_tokens t WHERE t.client_id = c.id)
		   AND NOT EXISTS (SELECT 1 FROM oauth_refresh_tokens t WHERE t.client_id = c.id)`,
	} {
		if _, err := db.pool.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
