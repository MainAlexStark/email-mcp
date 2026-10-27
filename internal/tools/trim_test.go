package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestTrimKeepsJSONValid — главное свойство обрезки: то, что доехало,
// должно разбираться. Битый JSON модель либо не поймёт, либо поймёт
// неправильно, и оба исхода хуже честного «данные неполны».
func TestTrimKeepsJSONValid(t *testing.T) {
	var items []any
	for i := 0; i < 500; i++ {
		items = append(items, map[string]any{
			"accrual_id": i,
			"comment":    strings.Repeat("длинный фрагмент письма ", 5),
		})
	}
	body, err := json.Marshal(map[string]any{"accruals": items, "last_id": "abc"})
	if err != nil {
		t.Fatal(err)
	}

	s := DefaultSafety()
	s.MaxResponseBytes = 10_000

	got := s.TrimResponse(string(body))
	if len(got) > s.MaxResponseBytes {
		t.Errorf("обрезанный ответ длиннее потолка: %d байт", len(got))
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("обрезанный ответ должен оставаться валидным JSON: %v", err)
	}
	if _, ok := doc[trimMarker]; !ok {
		t.Error("в обрезанном ответе должна стоять отметка об обрезке")
	}
	kept, ok := doc["accruals"].([]any)
	if !ok || len(kept) == 0 || len(kept) >= 500 {
		t.Errorf("массив должен укоротиться, а не исчезнуть: %d элементов", len(kept))
	}

	// Соседние поля не теряются: last_id нужен, чтобы продолжить обход.
	if doc["last_id"] != "abc" {
		t.Errorf("остальные поля должны сохраняться, получено %v", doc["last_id"])
	}
}

// TestTrimFindsNestedArray — списки писем лежат под result.
func TestTrimFindsNestedArray(t *testing.T) {
	var rows []any
	for i := 0; i < 300; i++ {
		rows = append(rows, map[string]any{"row": i, "text": strings.Repeat("x", 200)})
	}
	body, err := json.Marshal(map[string]any{
		"result":    map[string]any{"data": rows, "totals": []any{1, 2}},
		"timestamp": "2026-09-09",
	})
	if err != nil {
		t.Fatal(err)
	}

	s := DefaultSafety()
	s.MaxResponseBytes = 8_000
	got := s.TrimResponse(string(body))

	var doc map[string]any
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("вложенный массив должен обрезаться без порчи JSON: %v", err)
	}
	result, _ := doc["result"].(map[string]any)
	kept, _ := result["data"].([]any)
	if len(kept) == 0 || len(kept) >= 300 {
		t.Errorf("обрезаться должен самый длинный массив, получено %d элементов", len(kept))
	}
	if doc["timestamp"] != "2026-09-09" {
		t.Error("поля верхнего уровня должны сохраняться")
	}
}

// TestTrimNonJSONStaysValidUTF8 — обрубок текста не должен ломать
// кодировку: битый UTF-8 ломает уже не смысл, а протокол.
func TestTrimNonJSONStaysValidUTF8(t *testing.T) {
	s := DefaultSafety()
	s.MaxResponseBytes = 1_000

	got := s.TrimResponse(strings.Repeat("письмо ", 500))
	if !json.Valid([]byte(fmt.Sprintf("%q", got))) {
		t.Error("обрезанный текст должен оставаться корректным UTF-8")
	}
	if !strings.Contains(got, "обрезан") {
		t.Error("обрезка должна объясняться")
	}
}
