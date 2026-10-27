# Инструменты

35 инструментов. Имена и формат `message_id` — из [tecnologicachile/mail-mcp](https://github.com/tecnologicachile/mail-mcp): промпты и скрипты, написанные под него, работают без правки. Отличия — в конце.

Общие аргументы: `account_id` — ящик из `list_all_accounts` (можно не указывать, если ящик один); `message_id` — `imap:{account}:{mailbox}:{uidvalidity}:{uid}` из поиска; `mailbox` — имя папки или роль (`INBOX`, `Sent`, `Drafts`, `Trash`, `Junk`).

## Чтение — всегда

| Инструмент | Что делает |
|---|---|
| `list_all_accounts` | ящики подключения и его права; вызывается первым |
| `imap_list_accounts` | ящики с адресами IMAP-серверов (совместимость) |
| `imap_verify_account` | вход по IMAP и возможности сервера |
| `smtp_verify_account` | вход по SMTP без отправки |
| `imap_list_mailboxes` | папки с ролями (sent, drafts, trash, junk, archive) |
| `imap_mailbox_status` | всего и непрочитанных в папке, без загрузки писем |
| `imap_search_messages` | поиск в папке, новые первыми, постранично (`next_cursor`) |
| `imap_search_all_mailboxes` | один поиск во всех папках; вся переписка по `thread_message_id` |
| `imap_get_message` | письмо: заголовки, текст, вложения с `part_id`; очищенный HTML и текст PDF по запросу |
| `imap_get_message_raw` | исходник RFC 822 в base64 |
| `imap_get_attachment` | одно вложение: ссылка (сервис) или файл в «Загрузках» (stdio), base64 по запросу |
| `draft_list` | черновики с `draft_id` |
| `get_setup_guide` | серверы и пароль приложения для провайдера |
| `mail_status` | права, пороги, ящики |
| `mail_selftest` | проверка всех ящиков: IMAP, папки, SMTP |

Условия поиска: `query` (текст где угодно), `from`, `to`, `subject`, `thread_message_id`, `unread_only`, `last_days` или `start_date`/`end_date` (ГГГГ-ММ-ДД, включительно). Больше 20 000 совпадений — отказ с просьбой сузить.

## Черновики — право `mail:drafts` / `MAIL_ALLOW_DRAFTS`

| Инструмент | Что делает |
|---|---|
| `draft_create` | письмо в «Черновики»; ничего не отправляется |
| `draft_update` | замена черновика целиком; новый `draft_id`, сначала создаётся новый, потом удаляется старый |
| `draft_delete` | удалить черновик (`confirm: true`); только письма из черновиков |

## Изменение ящика — право `mail:write` / `MAIL_ALLOW_WRITES`

| Инструмент | Что делает |
|---|---|
| `imap_update_message_flags` | флаги письма: `\Seen`, `\Flagged`, свои метки |
| `imap_bulk_update_flags` | то же для пачки |
| `imap_move_message` / `imap_bulk_move` | перенос; возвращает `new_message_id` |
| `imap_copy_message` | копия в папку этого или другого ящика |
| `imap_delete_message` / `imap_bulk_delete` | удаление, `confirm: true`; **по умолчанию в корзину**, `permanent: true` — безвозвратно |
| `imap_search_and_move` / `imap_search_and_delete` | поиск и операция над найденным, до `limit` |
| `imap_create_mailbox` / `imap_rename_mailbox` | папки |
| `imap_delete_mailbox` | папка вместе с письмами, `confirm: true`; системные не удаляются |
| `imap_append_message` | положить готовое письмо RFC 822 в папку |

## Отправка — право `mail:send` / `MAIL_ALLOW_SEND`

| Инструмент | Что делает |
|---|---|
| `smtp_send_message` | новое письмо; копия в «Отправленные», где провайдер не кладёт её сам |
| `smtp_reply_message` | ответ: `Re:`, цепочка, цитата, `\Answered` на исходном; `reply_all` — всем, кроме себя |
| `smtp_forward_message` | пересылка с вложениями исходного письма |
| `draft_send` | отправить черновик и убрать его из черновиков; Bcc вырезается |

## Заслоны

- **Права** проверяются в `Registry.Add` до вызова — запрос, на который нет права, до почтового сервера не доходит (это проверяют тесты).
- **`confirm: true`** у удаления писем, папок и черновиков, у `imap_search_and_delete`.
- **Пакет** — не больше `MAIL_MAX_ITEMS_PER_WRITE` писем (100) за вызов.
- **Получатели** — больше `MAIL_MAX_RECIPIENTS` (10) только с `confirm_many_recipients: true`.
- **HTML в `body_text`** отклоняется: получатель увидел бы голые теги.
- **`file_path`** для вложений — только внутри `MAIL_ATTACHMENT_UPLOAD_DIR` (stdio), путь с раскрытыми `..` и симлинками; в сервисе — только `content_base64`.
- **Размер ответа** — не больше `MAIL_MAX_RESPONSE_BYTES`; длинный список обрезается по элементам с отметкой `_trimmed`.

## Отличия от mail-mcp

- Нет Microsoft Graph и EWS (`graph_send_message`, `ews_*`) — следующий этап; IMAP/SMTP покрывают Gmail, Яндекс, Mail.ru, iCloud, Zoho и хостинги.
- Права вместо трёх флагов: `MAIL_IMAP_WRITE_ENABLED`, `MAIL_DRAFTS_ENABLED`, `MAIL_SMTP_WRITE_ENABLED` по-прежнему понимаются как синонимы `MAIL_ALLOW_WRITES`, `MAIL_ALLOW_DRAFTS`, `MAIL_ALLOW_SEND`.
- Удаление по умолчанию уводит в корзину.
- Курсор поиска не хранится на сервере, а несёт условия в себе: сервер без состояния переживает перезапуск.
- Ответы — JSON без конверта `{summary, data, meta}`; `status`/`issues` там, где результат может быть частичным.
- Новые: `mail_status`, `mail_selftest`.
