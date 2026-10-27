# Почтовые провайдеры

В кабинете для этих доменов достаточно адреса и пароля приложения — серверы подставляются сами (`mail/providers.go`). Для stdio — те же значения в переменных `MAIL_IMAP_<ID>_*` / `MAIL_SMTP_<ID>_*`.

| Провайдер | IMAP | SMTP | Пароль |
|---|---|---|---|
| Gmail | imap.gmail.com:993 tls | smtp.gmail.com:465 tls | пароль приложения: myaccount.google.com/apppasswords (нужна двухэтапная проверка) |
| Яндекс | imap.yandex.ru:993 tls | smtp.yandex.ru:465 tls | пароль приложения: id.yandex.ru → Безопасность → Пароли приложений → Почта; включить IMAP в настройках почты |
| Mail.ru (bk, inbox, list) | imap.mail.ru:993 tls | smtp.mail.ru:465 tls | Настройки → Безопасность → Пароли для внешних приложений |
| Рамблер | imap.rambler.ru:993 tls | smtp.rambler.ru:465 tls | включить доступ из почтовых программ |
| iCloud | imap.mail.me.com:993 tls | smtp.mail.me.com:587 starttls | appleid.apple.com → Пароли приложений |
| Outlook.com | outlook.office365.com:993 tls | smtp-mail.outlook.com:587 starttls | Microsoft отключает вход по паролю для большинства ящиков; OAuth Microsoft — следующий этап |
| Zoho | imap.zoho.com:993 tls | smtp.zoho.com:465 tls | accounts.zoho.com → App Passwords |
| GMX | imap.gmx.com:993 tls | mail.gmx.com:587 starttls | обычный пароль, IMAP включается в настройках |

## Свой домен и хостинг

Обычно `imap.<домен>:993` (tls) и `smtp.<домен>:465` (tls) или `:587` (starttls). Если логин не совпадает с адресом (общий ящик), укажите его в «Серверы и логин».

## Копия в «Отправленных»

Gmail, Яндекс, Mail.ru, iCloud и Zoho сами кладут отправленное по SMTP в «Отправленные» — сервер свою копию не добавляет, иначе были бы дубли. Для остальных (Office 365, хостинги) копия кладётся через IMAP APPEND. Для stdio это переопределяется `MAIL_SMTP_<ID>_SAVE_SENT=true|false`.

## Папки

Модель может писать роли — `INBOX`, `Sent`, `Drafts`, `Trash`, `Junk` — сервер находит настоящие имена: по атрибутам SPECIAL-USE, а без них — по имени, включая русские («Отправленные», «Черновики», «Корзина», «Спам»).
