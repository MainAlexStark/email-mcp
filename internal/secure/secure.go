// Package secure — пароли, случайные секреты и шифрование паролей
// почтовых ящиков.
//
// Сервис хранит чужие пароли от почты, а пароль от почты — это доступ
// к сбросу паролей всех остальных сервисов человека. Поэтому они лежат
// в базе только зашифрованными (AES-256-GCM), а мастер-ключ живёт в
// окружении процесса, не в базе: утечка дампа без него бесполезна.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// RandomToken выдаёт криптостойкую случайную строку (32 байта, base64url).
func RandomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken — SHA-256 секрета для хранения. Для случайных токенов
// медленный хеш не нужен: перебирать 256 бит бессмысленно.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// keyVersion — первый байт шифротекста. Нужен, чтобы мастер-ключ
// можно было однажды сменить, не теряя способности прочитать старое.
const keyVersion byte = 1

// Cipher шифрует пароли ящиков.
type Cipher struct {
	aead cipher.AEAD
}

// ErrBadSecretKey — мастер-ключ не того размера или формата.
var ErrBadSecretKey = errors.New(
	"MAIL_SECRET_KEY должен быть 32 байтами в base64 — сгенерируйте: email-mcp --gen-secret")

// NewCipher создаёт шифр из мастер-ключа в base64 (32 байта).
func NewCipher(keyB64 string) (*Cipher, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		key, err = base64.RawURLEncoding.DecodeString(keyB64)
	}
	if err != nil || len(key) != 32 {
		return nil, ErrBadSecretKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// GenerateSecretKey выдаёт новый мастер-ключ в base64.
func GenerateSecretKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// Encrypt шифрует plaintext. aad привязывает шифротекст к записи
// (например, к владельцу ящика): переставить зашифрованный пароль
// в чужую строку базы и расшифровать его там не выйдет.
func (c *Cipher) Encrypt(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+c.aead.Overhead())
	out = append(out, keyVersion)
	out = append(out, nonce...)
	return c.aead.Seal(out, nonce, plaintext, aad), nil
}

// Decrypt расшифровывает результат Encrypt.
func (c *Cipher) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(ciphertext) < 1+ns+c.aead.Overhead() {
		return nil, errors.New("secure: шифротекст обрезан")
	}
	if ciphertext[0] != keyVersion {
		return nil, fmt.Errorf("secure: неизвестная версия ключа %d", ciphertext[0])
	}
	nonce := ciphertext[1 : 1+ns]
	plain, err := c.aead.Open(nil, nonce, ciphertext[1+ns:], aad)
	if err != nil {
		return nil, errors.New("secure: не расшифровать — сменился MAIL_SECRET_KEY или запись повреждена")
	}
	return plain, nil
}
