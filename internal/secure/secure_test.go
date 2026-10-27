package secure

import (
	"bytes"
	"testing"
)

func TestCipherRoundTripAndAAD(t *testing.T) {
	k, err := GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCipher(k)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := c.Encrypt([]byte("api-key"), []byte("shop-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("api-key")) {
		t.Fatal("ключ виден в шифротексте")
	}
	pt, err := c.Decrypt(ct, []byte("shop-1"))
	if err != nil || string(pt) != "api-key" {
		t.Fatalf("расшифровка: %q %v", pt, err)
	}
	if _, err := c.Decrypt(ct, []byte("shop-2")); err == nil {
		t.Fatal("шифротекст расшифровался с чужой привязкой")
	}

	other, _ := GenerateSecretKey()
	c2, _ := NewCipher(other)
	if _, err := c2.Decrypt(ct, []byte("shop-1")); err == nil {
		t.Fatal("расшифровалось чужим мастер-ключом")
	}
}

func TestBadSecretKey(t *testing.T) {
	for _, k := range []string{"", "short", "!!!"} {
		if _, err := NewCipher(k); err == nil {
			t.Fatalf("ключ %q принят", k)
		}
	}
}

func TestPasswordHash(t *testing.T) {
	if _, err := HashPassword("корот"); err != ErrShortPassword {
		t.Fatalf("короткий пароль: %v", err)
	}
	h, err := HashPassword("достаточно-длинный")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "достаточно-длинный") || VerifyPassword(h, "другой-пароль-123") {
		t.Fatal("проверка пароля")
	}
}
