package tools

import (
	"encoding/json"
	"fmt"
)

// Обрезка длинного ответа.
//
// Байтовый срез посреди JSON — худшее, что можно отдать модели: она
// получает синтаксически битый текст, не понимает, что данные неполны,
// и в лучшем случае повторяет вызов, а в худшем считает сумму по
// половине массива. Поэтому длинный ответ укорачивается по элементам
// самого объёмного массива: результат остаётся валидным JSON, а рядом
// с ним стоит отметка о том, сколько элементов осталось за кадром.

// trimMarker — ключ отметки об обрезке. Латиницей, потому что стоит
// рядом с полями писем и должен читаться как служебный, а не как данные.
const trimMarker = "_trimmed"

// maxTrimDepth ограничивает поиск массива вглубь ответа. Дальше третьего
// уровня («result» → «messages» → массив) инструменты списки не
// прячут, а обходить весь документ ради этого незачем.
const maxTrimDepth = 3

// trimJSON оставляет от самого длинного массива в документе столько
// элементов, сколько влезает в лимит, и возвращает валидный JSON.
//
// Второе значение — удалось ли обрезать осмысленно. false означает,
// что документ не JSON или в нём нет массива, по которому можно
// сокращать: тогда вызывающий режет по байтам и честно об этом
// предупреждает.
func trimJSON(body string, limit int) (string, bool) {
	var doc any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return "", false
	}

	path, list := longestArray(doc, maxTrimDepth)
	if list == nil {
		return "", false
	}
	total := len(list)

	// Двоичный поиск по числу оставленных элементов: сериализация
	// документа целиком стоит недёшево, а так их выходит около
	// log2(N) вместо N.
	best, bestOut := -1, ""
	lo, hi := 0, total
	for lo <= hi {
		keep := (lo + hi) / 2
		out, err := json.Marshal(withShortArray(doc, path, list[:keep], keep, total))
		if err != nil {
			return "", false
		}
		if len(out) <= limit {
			best, bestOut = keep, string(out)
			lo = keep + 1
		} else {
			hi = keep - 1
		}
	}

	// Даже пустой массив не влезает: сокращать нечего, документ длинный
	// сам по себе.
	if best < 0 {
		return "", false
	}
	return bestOut, true
}

// longestArray находит самый длинный массив в документе и путь к нему
// по именам полей. Пустой путь означает, что массив — сам документ.
func longestArray(doc any, depth int) ([]string, []any) {
	switch v := doc.(type) {
	case []any:
		return nil, v

	case map[string]any:
		if depth <= 0 {
			return nil, nil
		}
		var (
			bestPath []string
			bestList []any
		)
		for k, val := range v {
			path, list := longestArray(val, depth-1)
			if list == nil || len(list) <= len(bestList) {
				continue
			}
			bestPath = append([]string{k}, path...)
			bestList = list
		}
		return bestPath, bestList
	}
	return nil, nil
}

// withShortArray собирает копию документа, в которой массив по пути
// path заменён укороченным, и рядом стоит отметка об обрезке.
//
// Копия, а не правка на месте: двоичный поиск вызывает эту функцию
// несколько раз, и мутировать общий документ между попытками — верный
// способ получить в ответе следы предыдущей.
func withShortArray(doc any, path []string, short []any, keep, total int) any {
	if len(path) == 0 {
		// Обрезаемый массив — сам документ. Отметке нужен объект,
		// иначе её негде разместить.
		return map[string]any{
			trimMarker: trimNote(keep, total),
			"items":    short,
		}
	}

	out, ok := replaceAt(doc, path, short).(map[string]any)
	if !ok {
		return doc
	}
	// Отметка ставится на верхнем уровне: там её точно видно, даже
	// если сам массив лежит в глубине ответа.
	out[trimMarker] = trimNote(keep, total)
	return out
}

// replaceAt возвращает копию документа, в которой значение по пути path
// заменено на short. Объекты по дороге копируются, всё остальное
// переиспользуется как есть.
func replaceAt(doc any, path []string, short []any) any {
	if len(path) == 0 {
		return short
	}
	src, ok := doc.(map[string]any)
	if !ok {
		return doc
	}
	out := make(map[string]any, len(src)+1)
	for k, v := range src {
		out[k] = v
	}
	head := path[0]
	out[head] = replaceAt(src[head], path[1:], short)
	return out
}

// trimNote описывает обрезку словами, а не одним числом: модель должна
// понять, что делать дальше, а не только что данные неполны.
func trimNote(keep, total int) map[string]any {
	return map[string]any{
		"оставлено": keep,
		"всего":     total,
		"почему":    "ответ обрезан: он длиннее потолка, заданного сервером",
		"что_делать": fmt.Sprintf(
			"это первые %d элементов из %d, остальные не отправлены — повторный вызов "+
				"с теми же аргументами вернёт ровно то же самое. Сузьте выборку: "+
				"меньший limit, фильтр по отправителю, теме или датам, меньший body_max_chars. "+
				"Для писем есть постраничный поиск — next_cursor",
			keep, total),
	}
}
