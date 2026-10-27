# Сервис: один сервер на много пользователей

Тот же бинарник работает двумя способами:

- **stdio** — Claude запускает сервер подпроцессом на вашей машине. Ящики и права — в окружении, в формате исходного mail-mcp. Для личного использования.
- **сервис** (`--http`) — сервер на VPS с PostgreSQL. Пользователи регистрируются, подключают свои ящики в кабинете и добавляют сервер в Claude по одному адресу. Каждое подключение Claude — все ящики пользователя или один, с правами, отмеченными на экране согласия.

## Что внутри

```
                    https://mail-mcp.example.com
                               │
                             Caddy (TLS)
                               │
                           email-mcp
   ┌───────────────┬───────────┴──────────┬──────────────────┬──────────┐
   /  /signup       /oauth/*              /mcp               /files/*   /healthz
   /login /account  регистрация клиента,  инструменты:       вложения   живость
   кабинет          согласие, токены      токен → пользователь  по ссылке
                                          → ящики → IMAP/SMTP
                               │
                          PostgreSQL
   пользователи · ящики (пароли зашифрованы) · приглашения · сессии · OAuth · API-токены · учёт вызовов
```

На каждый запрос к `/mcp` сервер отвечает на три вопроса: чей токен, к каким ящикам он выдан и с какими правами. Права процесса в сервисе не действуют: все разрешения берутся из токена, из настроек процесса — только пороги.

Подключение к почтовому серверу открывается на одну операцию и закрывается после неё. Держать IMAP-сессию на каждого пользователя значило бы упереться в лимиты провайдеров (Gmail — 15 соединений на ящик) и разбираться с обрывами посреди простоя.

## Развёртывание: одна команда

Нужен VPS с Docker и A-запись домена на его адрес:

```
mail-mcp.example.com    A    <адрес VPS>
```

```bash
git clone https://github.com/MainAlexStark/email-mcp
cd email-mcp
./deploy.sh mail-mcp.example.com
# или сразу с регистрацией по приглашениям:
MAIL_REGISTRATION=invite ./deploy.sh mail-mcp.example.com
```

Скрипт:

1. заведёт сеть `mcp-network` и поднимет общий Caddy в `/opt/infrastructure`, если его ещё нет;
2. впишет домен в его `Caddyfile` между маркерами `# >>> email-mcp` и `# <<<`;
3. придумает пароль базы (`deploy/postgres.env`) и мастер-ключ шифрования (`MAIL_SECRET_KEY` в `deploy/email-mcp.env`), оба файла с правами 600;
4. соберёт образ и поднимет сервис вместе с PostgreSQL; миграции сервер применяет сам на старте;
5. дождётся `200` от `https://<домен>/healthz`.

Повторный запуск ничего не ломает: секреты не перевыпускаются.

Исходящие соединения: IMAP 993/143 и SMTP 465/587 к серверам пользователей. Некоторые VPS-провайдеры закрывают исходящий 25 и иногда 465/587 — если отправка ни у кого не проходит, а вход по IMAP работает, спросите провайдера VPS.

### Мастер-ключ

`MAIL_SECRET_KEY` шифрует пароли ящиков в базе (AES-256-GCM).

- **Не терять.** Без него зашифрованные пароли не прочитать — всем придётся подключать ящики заново. Копия — `./deploy.sh secrets`.
- **Не хранить рядом с дампами базы.** Дамп без ключа бесполезен; дамп вместе с ключом раскрывает пароли всех ящиков.

## Регистрация

| `MAIL_REGISTRATION` | Кто может зарегистрироваться |
|---|---|
| `open` (по умолчанию) | любой |
| `invite` | только с кодом приглашения |
| `closed` | никто; существующие пользователи работают |

Смена режима: правка `deploy/email-mcp.env` и `./deploy.sh restart`.

Приглашения:

```bash
./deploy.sh invite          # одно приглашение
./deploy.sh invite 5 "команда"   # пять, с пометкой
./deploy.sh invites         # список: кому выдано, использовано ли
```

Печатаются ссылки вида `https://<домен>/signup?invite=…` — код уже подставлен в форму. Каждое приглашение — на одну регистрацию, по умолчанию живёт 14 дней (`--invite-ttl 0` — бессрочно). Код показывается один раз: в базе только его хеш.

## Обновление: одна команда

```bash
./deploy.sh update
```

`git pull --ff-only`, недостающие секреты, резервная копия базы в `backups/`, пересборка, ожидание `/healthz`. **Если новая версия не отвечает — скрипт откатывает код на прежний коммит.**

## Остальные команды

```bash
./deploy.sh status     # что запущено и отвечает ли сервер
./deploy.sh logs       # журнал сервера
./deploy.sh backup     # дамп базы в backups/ (сжатый, права 600)
./deploy.sh users      # пользователи: ящики, вызовы за 30 дней, статус
./deploy.sh secrets    # адрес и мастер-ключ
./deploy.sh restart
./deploy.sh down
```

## Администрирование

```bash
sudo docker compose exec email-mcp /email-mcp --users
sudo docker compose exec email-mcp /email-mcp --disable user@example.com
sudo docker compose exec email-mcp /email-mcp --enable user@example.com
sudo docker compose exec -i email-mcp /email-mcp --set-password user@example.com
```

- `--disable` сразу закрывает кабинет, все подключения Claude и API-токены пользователя. Данные остаются.
- `--set-password` — для тех, кто забыл пароль от кабинета. Пароль читается со stdin.

## Если сервер не ответил

1. **DNS.** `dig +short mail-mcp.example.com` должен вернуть адрес этого VPS.
2. **Порты 80 и 443.** Без них Let's Encrypt не выдаст сертификат.
3. **Сервер упал на старте.** `./deploy.sh logs`. Типичные причины: не задан или испорчен `MAIL_SECRET_KEY`, база не поднялась, неверный `MAIL_DATABASE_URL`, опечатка в `MAIL_REGISTRATION`.

`/healthz` отвечает `503`, если сервер жив, а база нет.

## Вручную, под systemd

```bash
go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o /usr/local/bin/email-mcp ./cmd/email-mcp

sudo -u postgres createuser mail --pwprompt
sudo -u postgres createdb -O mail mail

sudo useradd --system --no-create-home --shell /usr/sbin/nologin emailmcp
sudo install -m 600 deploy/email-mcp.env.example /etc/email-mcp.env
email-mcp --gen-secret             # → MAIL_SECRET_KEY
sudo nano /etc/email-mcp.env       # адрес, база, мастер-ключ, регистрация

sudo cp deploy/email-mcp.service /etc/systemd/system/
sudo systemctl enable --now email-mcp
```

Юнит слушает `127.0.0.1:8572`, TLS — за обратным прокси.

## Устройство транспорта

Сервер без состояния: `Mcp-Session-Id` не выдаётся и не требуется. Курсор постраничного поиска тоже не хранится на сервере: условия поиска и позиция зашиты в сам `next_cursor`.

- `POST /mcp` — JSON-RPC внутрь, JSON наружу.
- `GET /mcp` и `DELETE /mcp` — `405`.
- Уведомления — `202` без тела.
- `Origin` на `/mcp` проверяется.
- Токен к удалённому ящику — `403`, а не `401`: на `401` клиент бросился бы обновлять токен и зациклился.
- `/files/<токен>/<имя>` — вложения, скачанные через `imap_get_attachment`. Без авторизации: ссылку открывает браузер человека; доступ держится на 128 битах случайности в пути и коротком сроке жизни (`MAIL_FILES_TTL`, по умолчанию час). Хранятся только в памяти.

### Свои скрипты: API-токены

В кабинете выпускаются персональные токены (`emc_…`): ко всем ящикам или к одному, с отмеченными правами, бессрочные, отзываются кнопкой. Показываются один раз.

```bash
curl -sS https://mail-mcp.example.com/mcp \
  -H "Authorization: Bearer $EMC_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"imap_search_messages","arguments":{"mailbox":"INBOX","unread_only":true}}}'
```
