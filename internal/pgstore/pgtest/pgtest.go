// Package pgtest — база для тестов.
//
// Тесты, которым нужен PostgreSQL, берут адрес из MAIL_TEST_DATABASE_URL
// и пропускаются, если он не задан: `go test ./...` на машине без базы
// должен оставаться зелёным. В CI база поднимается сервисом (см.
// .github/workflows/ci.yml), локально — например так:
//
//	docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=test postgres:16
//	export MAIL_TEST_DATABASE_URL=postgres://postgres:test@localhost:5432/postgres
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/MainAlexStark/email-mcp/internal/pgstore"
)

// Open подключается к тестовой базе и применяет миграции.
func Open(t testing.TB) *pgstore.DB {
	t.Helper()
	url := os.Getenv("MAIL_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("MAIL_TEST_DATABASE_URL не задан — тест с PostgreSQL пропущен")
	}
	ctx := context.Background()
	db, err := pgstore.Open(ctx, url)
	if err != nil {
		t.Fatalf("тестовая база: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		t.Fatalf("миграции: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// Email — уникальный адрес: тесты делят одну базу и не должны мешать
// друг другу.
func Email(prefix string) string {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	return prefix + "-" + hex.EncodeToString(buf) + "@example.com"
}
