# email-mcp

MCP-сервер почты для Claude: поиск, чтение, черновики, разбор папок и отправка — по IMAP и SMTP. Gmail, Яндекс, Mail.ru, iCloud, Zoho и любой ящик с IMAP.

Основа — [tecnologicachile/mail-mcp](https://github.com/tecnologicachile/mail-mcp) (Rust, MIT): тот же набор инструментов, те же имена и формат `message_id`. Переписан на Go по [нашему стандарту](STANDARD.md) и дополнен многопользовательским сервисом: регистрация, кабинет, ящики пользователей с зашифрованными паролями, OAuth для Claude и развёртывание на VPS одной командой.

## Два режима

**Сервис** — один сервер на много людей. Каждый регистрируется, подключает свои ящики (адрес + пароль приложения, серверы известных провайдеров подставляются сами) и добавляет в Claude коннектор `https://<домен>/mcp`. На экране согласия человек выбирает, к каким ящикам (всем или одному) и с какими правами (чтение, черновики, изменение ящика, отправка) подключается приложение.

```bash
./deploy.sh mail-mcp.example.com                    # развернуть
MAIL_REGISTRATION=invite ./deploy.sh mail-mcp.example.com   # только по приглашениям
./deploy.sh invite 3                                # выпустить приглашения
./deploy.sh update                                  # обновить, с откатом при неудаче
```

Подробно — [docs/REMOTE.md](docs/REMOTE.md), про подключение и права — [docs/OAUTH.md](docs/OAUTH.md).

**stdio** — Claude запускает сервер на вашей машине. Конфигурация — в формате исходного mail-mcp:

```bash
go install github.com/MainAlexStark/email-mcp/cmd/email-mcp@latest

MAIL_IMAP_WORK_HOST=imap.yandex.ru \
MAIL_IMAP_WORK_USER=you@yandex.ru \
MAIL_IMAP_WORK_PASS=пароль-приложения \
MAIL_SMTP_WORK_HOST=smtp.yandex.ru MAIL_SMTP_WORK_SECURE=tls \
email-mcp --check
```

```json
{
  "mcpServers": {
    "mail": {
      "command": "email-mcp",
      "env": {
        "MAIL_IMAP_WORK_HOST": "imap.yandex.ru",
        "MAIL_IMAP_WORK_USER": "you@yandex.ru",
        "MAIL_IMAP_WORK_PASS": "пароль-приложения",
        "MAIL_SMTP_WORK_HOST": "smtp.yandex.ru",
        "MAIL_SMTP_WORK_SECURE": "tls",
        "MAIL_ALLOW_DRAFTS": "true"
      }
    }
  }
}
```

Серверы и пароли приложений провайдеров — [docs/PROVIDERS.md](docs/PROVIDERS.md).

## Права и заслоны

По умолчанию — только чтение. Остальное открывается по отдельности: в stdio — `MAIL_ALLOW_DRAFTS`, `MAIL_ALLOW_WRITES`, `MAIL_ALLOW_SEND`; в сервисе — галочками на экране согласия.

- удаление по умолчанию уводит письма в корзину и требует `confirm: true`;
- письмо больше чем на 10 адресов — только с `confirm_many_recipients: true`;
- пакетные операции — не больше 100 писем за вызов;
- в сервисе пароли ящиков зашифрованы AES-256-GCM, внутренние адреса и соединения без TLS запрещены.

Полный список инструментов — [docs/TOOLS.md](docs/TOOLS.md).

## Разработка

```bash
make check      # gofmt, vet, тесты с -race
make test-db    # тесты вместе с PostgreSQL (Docker)
```

Тесты ходят в настоящие IMAP и SMTP в памяти (`mail/mailtest`), инструменты вызываются через протокол MCP, сервис — через HTTP с настоящей базой.

```
cmd/email-mcp/        флаги, окружение, stdio и сервис, команды администратора
mail/                 клиент ящика: IMAP, SMTP, MIME, черновики, провайдеры
internal/tools/       инструменты, права, заслоны, обрезка ответа
internal/mcp, mcptest тонкий слой над go-sdk и клиент для тестов
internal/httpx        сетевой транспорт: токен → пользователь → ящики → права
internal/oauth        OAuth 2.1: DCR, PKCE, согласие с выбором ящиков и прав
internal/web          регистрация (open/invite/closed), кабинет
internal/mailboxes    проверка и шифрование ящиков пользователей
internal/pgstore      PostgreSQL
```

## Лицензия

MIT. Набор инструментов и их контракт — из mail-mcp (tecnologicachile), его лицензия приложена в [LICENSE](LICENSE).
