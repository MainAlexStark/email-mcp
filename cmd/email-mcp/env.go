package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MainAlexStark/email-mcp/mail"
)

// Ящики stdio-режима читаются из окружения в формате исходного
// mail-mcp — конфигурацию, написанную для него, можно перенести как есть:
//
//	MAIL_IMAP_<ID>_HOST, _PORT (993), _SECURE (true|false|starttls), _USER, _PASS
//	MAIL_SMTP_<ID>_HOST, _PORT (587), _SECURE (starttls|true|false), _USER, _PASS
//	MAIL_SMTP_<ID>_FROM_EMAIL, _FROM_NAME, _SAVE_SENT
//
// <ID> — имя ящика; модель видит его в нижнем регистре: WORK → work.
func envAccounts() ([]mail.Account, error) {
	ids := map[string]bool{}
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if rest, ok := strings.CutPrefix(key, "MAIL_IMAP_"); ok {
			if id, ok := strings.CutSuffix(rest, "_HOST"); ok && id != "" {
				ids[id] = true
			}
		}
	}
	var list []string
	for id := range ids {
		list = append(list, id)
	}
	sort.Strings(list)

	timeout := envDuration("MAIL_TIMEOUT", mail.DefaultTimeout)
	var out []mail.Account
	for _, id := range list {
		acc, err := envAccount(id, timeout)
		if err != nil {
			return nil, err
		}
		out = append(out, acc)
	}
	return out, nil
}

func envAccount(id string, timeout time.Duration) (mail.Account, error) {
	imapP, smtpP := "MAIL_IMAP_"+id+"_", "MAIL_SMTP_"+id+"_"
	get := func(k string) string { return strings.TrimSpace(os.Getenv(k)) }

	acc := mail.Account{
		ID:       strings.ToLower(id),
		Username: get(imapP + "USER"),
		Password: os.Getenv(imapP + "PASS"),
		Timeout:  timeout,
	}
	sec, err := mail.ParseSecurity(get(imapP + "SECURE"))
	if err != nil {
		return acc, fmt.Errorf("%sSECURE: %w", imapP, err)
	}
	port, err := envPort(imapP+"PORT", map[bool]int{true: 993, false: 143}[sec == mail.SecurityTLS])
	if err != nil {
		return acc, err
	}
	acc.IMAP = mail.Server{Host: get(imapP + "HOST"), Port: port, Security: sec}

	if h := get(smtpP + "HOST"); h != "" {
		raw := get(smtpP + "SECURE")
		if raw == "" {
			raw = "starttls" // как в исходном mail-mcp: по умолчанию 587 + STARTTLS
		}
		ssec, err := mail.ParseSecurity(raw)
		if err != nil {
			return acc, fmt.Errorf("%sSECURE: %w", smtpP, err)
		}
		def := 587
		if ssec == mail.SecurityTLS {
			def = 465
		}
		sport, err := envPort(smtpP+"PORT", def)
		if err != nil {
			return acc, err
		}
		acc.SMTP = mail.Server{Host: h, Port: sport, Security: ssec}
		if u := get(smtpP + "USER"); u != "" && u != acc.Username {
			acc.SMTPUsername, acc.SMTPPassword = u, os.Getenv(smtpP+"PASS")
		}
		acc.Email = get(smtpP + "FROM_EMAIL")
		if acc.Email == "" && acc.SMTPUsername != "" && strings.Contains(acc.SMTPUsername, "@") {
			acc.Email = acc.SMTPUsername
		}
		acc.DisplayName = get(smtpP + "FROM_NAME")
		if v := get(smtpP + "SAVE_SENT"); v != "" {
			b := envTrue(v)
			acc.SaveSent = &b
		} else if v := get("MAIL_SMTP_SAVE_SENT"); v != "" {
			b := envTrue(v)
			acc.SaveSent = &b
		}
	}
	if err := acc.Validate(); err != nil {
		return acc, fmt.Errorf("ящик %s: %w", id, err)
	}
	return acc, nil
}

func envPort(key string, def int) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 || n > 65535 {
		return 0, fmt.Errorf("%s: порт — число от 1 до 65535, получено %q", key, v)
	}
	return n, nil
}

func envTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// envBool — true, если задана хоть одна из переменных. Вторые имена —
// из исходного mail-mcp, чтобы перенесённая конфигурация не теряла
// права молча.
func envBool(keys ...string) bool {
	for _, k := range keys {
		if envTrue(os.Getenv(k)) {
			return true
		}
	}
	return false
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
