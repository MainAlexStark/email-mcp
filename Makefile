.PHONY: build tidy test test-db check install fmt verify deploy update

build:
	go build -o bin/email-mcp ./cmd/email-mcp

# go.mod/go.sum в порядок. Без Go на машине — через Docker.
tidy:
	@if command -v go >/dev/null 2>&1; then go mod tidy; \
	else docker run --rm -v "$$PWD":/src -w /src golang:1.25-alpine go mod tidy; fi

install:
	go install ./cmd/email-mcp

test:
	go test ./...

# Тесты вместе с хранилищем и кабинетом — против настоящего PostgreSQL.
test-db:
	docker rm -f email-mcp-testdb >/dev/null 2>&1 || true
	docker run --rm -d --name email-mcp-testdb -p 55432:5432 -e POSTGRES_PASSWORD=test postgres:16-alpine >/dev/null
	until docker exec email-mcp-testdb pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
	MAIL_TEST_DATABASE_URL=postgres://postgres:test@localhost:55432/postgres?sslmode=disable go test -race -count=1 ./... ; \
	  status=$$?; docker rm -f email-mcp-testdb >/dev/null; exit $$status

fmt:
	gofmt -w .

check: fmt
	go vet ./...
	go test -race ./...

# Проверить ящики из окружения (stdio), не запуская сервер.
verify:
	go run ./cmd/email-mcp --check

# Развернуть на VPS: make deploy DOMAIN=mail-mcp.example.com
deploy:
	./deploy.sh $(DOMAIN)

# Обновить развёрнутый сервер до свежего коммита.
update:
	./deploy.sh update
