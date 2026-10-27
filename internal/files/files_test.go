package files

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDirDoesNotOverwriteSameSecond(t *testing.T) {
	// Два вложения с одним именем в одну секунду — обычное дело. Вторая не
	// должна затирать первую: её могли ещё не распечатать.
	d, err := NewDir(t.TempDir() + "/labels")
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return fixed }

	a, err := d.Save("labels.pdf", "application/pdf", []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.Save("labels.pdf", "application/pdf", []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Location == b.Location {
		t.Fatalf("второй файл перезаписал первый: %s", a.Location)
	}
	if got, _ := os.ReadFile(a.Location); string(got) != "one" {
		t.Error("содержимое первого файла испорчено")
	}
}

func TestSafeNameStripsPathAndAddsExt(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd": "passwd.pdf",
		"акт 42":           "акт_42.pdf",
		"":                 "document.pdf",
		"label.pdf":        "label.pdf",
	}
	for in, want := range cases {
		if got := safeName(in, "application/pdf"); got != want {
			t.Errorf("safeName(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

func TestMemoryServesUntilExpiry(t *testing.T) {
	m := NewMemory("https://mcp.example.com/", time.Hour, 1<<20)
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	saved, err := m.Save("labels.pdf", "application/pdf", []byte("%PDF-1.4"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(saved.Location, "https://mcp.example.com/files/") {
		t.Fatalf("ссылка должна вести на сервис: %s", saved.Location)
	}
	path := strings.TrimPrefix(saved.Location, "https://mcp.example.com")

	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "%PDF-1.4" {
		t.Fatalf("файл не отдан: %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/pdf" {
		t.Errorf("Content-Type: %s", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
		t.Error("ссылка — право доступа, кешировать её нельзя")
	}

	// Угадать соседний токен нельзя: чужой путь — 404.
	rec = httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/files/00000000000000000000000000000000/labels.pdf", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("неизвестный токен: ожидался 404, получено %d", rec.Code)
	}

	now = now.Add(2 * time.Hour)
	rec = httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("истёкшая ссылка должна давать 404, получено %d", rec.Code)
	}
}

func TestMemoryEvictsOldestWhenFull(t *testing.T) {
	m := NewMemory("https://x", time.Hour, 10)

	first, _ := m.Save("a.pdf", "application/pdf", []byte("123456"))
	if _, err := m.Save("b.pdf", "application/pdf", []byte("789012")); err != nil {
		t.Fatal(err)
	}
	if m.total > 10 {
		t.Errorf("объём превысил потолок: %d", m.total)
	}

	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, strings.TrimPrefix(first.Location, "https://x"), nil))
	if rec.Code != http.StatusNotFound {
		t.Error("старый файл должен вытесняться, когда новый не помещается")
	}

	if _, err := m.Save("big.pdf", "application/pdf", make([]byte, 11)); err == nil {
		t.Error("файл больше потолка должен отклоняться")
	}
}
