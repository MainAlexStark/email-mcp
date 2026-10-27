package secure

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"crypto/pbkdf2"
)

// Пароль пользователя хранится не в открытом виде, а как PBKDF2-хеш.
//
// Простой SHA-256 здесь не годится: он считается миллиардами в секунду,
// и перебор короткого пароля занял бы минуты. PBKDF2 с большим числом
// итераций делает каждую попытку дорогой.
//
// Формат строки: pbkdf2-sha256$<итерации>$<соль>$<хеш>, обе части
// в base64. Всё нужное для проверки лежит внутри, поэтому смена числа
// итераций не ломает старые хеши.

const (
	pbkdf2Iterations = 600_000 // ориентир OWASP для PBKDF2-SHA256
	pbkdf2KeyLength  = 32
	pbkdf2SaltLength = 16
)

// MinPasswordLen — минимальная длина пароля пользователя.
const MinPasswordLen = 8

// ErrShortPassword — пароль короче MinPasswordLen.
var ErrShortPassword = errors.New("пароль короче 8 символов: он защищает доступ к вашей почте, возьмите длиннее")

// HashPassword считает хеш пароля.
func HashPassword(password string) (string, error) {
	if len([]rune(password)) < MinPasswordLen {
		return "", ErrShortPassword
	}

	salt := make([]byte, pbkdf2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLength)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s",
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword проверяет пароль против хеша.
func VerifyPassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}

	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}

	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}

	// Сравнение за постоянное время: обычное == раскрывает по времени
	// длину совпавшего префикса.
	return subtle.ConstantTimeCompare(got, want) == 1
}
