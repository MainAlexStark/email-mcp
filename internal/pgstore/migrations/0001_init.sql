-- Схема сервиса: пользователи, их почтовые ящики, вход в кабинет,
-- приглашения, OAuth-подключения Claude, персональные API-токены и учёт
-- вызовов.
--
-- Всё, что принадлежит пользователю, удаляется вместе с ним
-- (ON DELETE CASCADE): удаление аккаунта обязано убирать и пароли
-- ящиков, и все выданные доступы, а не оставлять их висеть без хозяина.

CREATE TABLE users (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email             text        NOT NULL,
    password_hash     text        NOT NULL,
    -- Тариф. Пока у всех free; поле заведено сразу, чтобы монетизация
    -- не начиналась с миграции живой таблицы.
    plan              text        NOT NULL DEFAULT 'free',
    email_verified_at timestamptz,
    disabled_at       timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_login_at     timestamptz
);
-- Регистр адреса не различаем: Alex@ и alex@ — один человек.
CREATE UNIQUE INDEX users_email_key ON users (lower(email));

-- Приглашения для режима MAIL_REGISTRATION=invite. В базе только хеш
-- кода: утечка базы не даёт готовых приглашений.
CREATE TABLE invites (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code_hash  text        NOT NULL UNIQUE,
    note       text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    used_at    timestamptz,
    used_by    bigint      REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE mailboxes (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Короткое имя, которое модель передаёт как account_id.
    name          text        NOT NULL,
    email         text        NOT NULL,
    display_name  text        NOT NULL DEFAULT '',
    imap_host     text        NOT NULL,
    imap_port     integer     NOT NULL,
    imap_security text        NOT NULL,
    -- SMTP может быть не задан: ящик только для чтения.
    smtp_host     text        NOT NULL DEFAULT '',
    smtp_port     integer     NOT NULL DEFAULT 0,
    smtp_security text        NOT NULL DEFAULT '',
    username      text        NOT NULL,
    -- Пароль зашифрован AES-256-GCM мастер-ключом из окружения
    -- (MAIL_SECRET_KEY). Открытого пароля в базе нет.
    password_enc  bytea       NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    checked_at    timestamptz,
    check_error   text        NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX mailboxes_user_name_key ON mailboxes (user_id, lower(name));

CREATE TABLE web_sessions (
    token_hash text        PRIMARY KEY,
    user_id    bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf       text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX web_sessions_user_idx ON web_sessions (user_id);

CREATE TABLE oauth_clients (
    id            text        PRIMARY KEY,
    secret_hash   text        NOT NULL DEFAULT '',
    name          text        NOT NULL DEFAULT '',
    redirect_uris text[]      NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oauth_login_sessions (
    id             text        PRIMARY KEY,
    client_id      text        NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    redirect_uri   text        NOT NULL,
    state          text        NOT NULL,
    scopes         text[]      NOT NULL,
    resource       text        NOT NULL,
    code_challenge text        NOT NULL,
    user_id        bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at     timestamptz NOT NULL
);

-- mailbox_id NULL — подключение ко всем ящикам пользователя (и к тем,
-- что он добавит позже). Конкретный ящик — каскад: подключение к
-- удалённому ящику не должно работать ни минуты.
CREATE TABLE oauth_codes (
    code_hash      text        PRIMARY KEY,
    client_id      text        NOT NULL,
    redirect_uri   text        NOT NULL,
    scopes         text[]      NOT NULL,
    resource       text        NOT NULL,
    code_challenge text        NOT NULL,
    user_id        bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    mailbox_id     bigint      REFERENCES mailboxes (id) ON DELETE CASCADE,
    expires_at     timestamptz NOT NULL
);

CREATE TABLE oauth_access_tokens (
    token_hash text        PRIMARY KEY,
    grant_id   text        NOT NULL,
    client_id  text        NOT NULL,
    scopes     text[]      NOT NULL,
    resource   text        NOT NULL,
    user_id    bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    mailbox_id bigint      REFERENCES mailboxes (id) ON DELETE CASCADE,
    issued_at  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX oauth_access_tokens_grant_idx ON oauth_access_tokens (grant_id);
CREATE INDEX oauth_access_tokens_user_idx ON oauth_access_tokens (user_id);

CREATE TABLE oauth_refresh_tokens (
    token_hash text        PRIMARY KEY,
    grant_id   text        NOT NULL,
    client_id  text        NOT NULL,
    scopes     text[]      NOT NULL,
    resource   text        NOT NULL,
    user_id    bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    mailbox_id bigint      REFERENCES mailboxes (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);
CREATE INDEX oauth_refresh_tokens_grant_idx ON oauth_refresh_tokens (grant_id);
CREATE INDEX oauth_refresh_tokens_user_idx ON oauth_refresh_tokens (user_id);

-- Персональные токены для автоматизации, которая не может пройти
-- экран согласия. Бессрочные, отзываются в кабинете.
CREATE TABLE api_tokens (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash   text        NOT NULL UNIQUE,
    user_id      bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    mailbox_id   bigint      REFERENCES mailboxes (id) ON DELETE CASCADE,
    name         text        NOT NULL,
    scopes       text[]      NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);
CREATE INDEX api_tokens_user_idx ON api_tokens (user_id);

-- Счётчик вызовов инструментов по дням — основа будущих тарифов
-- и ответ на вопрос «кто и чем пользуется». mailbox_id 0 — подключение
-- ко всем ящикам.
CREATE TABLE usage_daily (
    user_id    bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    mailbox_id bigint NOT NULL,
    day        date   NOT NULL,
    tool       text   NOT NULL,
    calls      bigint NOT NULL DEFAULT 0,
    errors     bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, mailbox_id, day, tool)
);
