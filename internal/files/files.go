// Package files — куда девать вложения писем, которые просит модель.
//
// Счёт, договор, скан — это PDF или картинка, а инструмент MCP возвращает
// текст. Вставить PDF в ответ base64-строкой можно, но бесполезно:
// 200 КБ вложения — это 270 КБ текста, которые клиент обрежет по
// токенам, а человеку всё равно нужен файл, чтобы открыть его.
// Поэтому файл кладётся туда, откуда его можно открыть, а модель
// получает ссылку.
//
// Куда именно — зависит от режима:
//
//   - stdio: сервер работает на машине человека, и лучший адрес — папка
//     на диске (Dir). Путь открывается двойным щелчком.
//
//   - сервис: диска человека у сервера нет. Файл держится в памяти
//     процесса (Memory) и отдаётся по ссылке с неугадываемым токеном,
//     которая живёт ограниченное время.
package files

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Saved — где теперь лежит файл.
type Saved struct {
	// Location — то, что показать человеку: путь на диске или ссылка.
	Location string
	Name     string
	Size     int

	// Expires — когда ссылка перестанет работать. Нулевое значение —
	// файл лежит, пока его не удалят.
	Expires time.Time
}

// Store сохраняет файл и говорит, где его взять.
type Store interface {
	Save(name, contentType string, data []byte) (Saved, error)
}

// ErrTooLarge — файл больше, чем хранилище готово принять.
var ErrTooLarge = errors.New("files: файл слишком большой")

// --- Папка на диске ---

// Dir складывает файлы в папку. Для stdio.
type Dir struct {
	Root string
	now  func() time.Time
}

// NewDir создаёт хранилище в папке.
//
// Сама папка создаётся при первом сохранении, а не здесь: сервер
// стартует при каждом запуске Claude, и заводить человеку пустую
// папку в «Загрузках», пока он не скачал ни одного вложения, незачем.
func NewDir(root string) (*Dir, error) {
	if root == "" {
		return nil, errors.New("files: не задана папка")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("files: %w", err)
	}
	return &Dir{Root: abs, now: time.Now}, nil
}

// DefaultDir — папка по умолчанию: «Загрузки/email-mcp», а если такой нет —
// временная папка системы.
//
// Загрузки выбраны потому, что человек ищет скачанное именно там,
// а вложение для него и есть скачанный файл.
func DefaultDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		dl := filepath.Join(home, "Downloads")
		if st, err := os.Stat(dl); err == nil && st.IsDir() {
			return filepath.Join(dl, "email-mcp")
		}
	}
	return filepath.Join(os.TempDir(), "email-mcp")
}

// Save пишет файл. Имя дополняется временем, чтобы второе вложение
// с тем же именем не перетирало первое.
func (d *Dir) Save(name, contentType string, data []byte) (Saved, error) {
	if err := os.MkdirAll(d.Root, 0o755); err != nil {
		return Saved{}, fmt.Errorf("files: не создать папку %s: %w", d.Root, err)
	}
	first := stamped(safeName(name, contentType), d.now())
	ext := filepath.Ext(first)

	// Два вызова в одну секунду дают одно имя. O_EXCL вместо проверки
	// «есть ли файл»: между проверкой и записью файл может появиться.
	for i := 1; i <= 100; i++ {
		base := first
		if i > 1 {
			base = fmt.Sprintf("%s-%d%s", strings.TrimSuffix(first, ext), i, ext)
		}
		path := filepath.Join(d.Root, base)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return Saved{}, fmt.Errorf("files: запись %s: %w", path, err)
		}
		_, werr := f.Write(data)
		cerr := f.Close()
		if werr != nil || cerr != nil {
			return Saved{}, fmt.Errorf("files: запись %s: %w", path, errors.Join(werr, cerr))
		}
		return Saved{Location: path, Name: base, Size: len(data)}, nil
	}
	return Saved{}, fmt.Errorf("files: не подобрать свободное имя для %s в %s", first, d.Root)
}

// --- Память процесса со ссылками ---

// Memory держит файлы в памяти и отдаёт их по ссылке. Для сервиса.
//
// Ссылка — это и есть право доступа: 128 бит случайности в пути,
// без авторизации. Иначе открыть вложение в браузере не получилось бы
// вовсе: у браузера нет токена, которым Claude ходит в /mcp. Поэтому
// ссылка короткоживущая, а содержимое не переживает перезапуск.
type Memory struct {
	// BaseURL — внешний адрес сервиса без завершающей косой черты.
	BaseURL string
	// TTL — сколько живёт ссылка.
	TTL time.Duration
	// MaxBytes — потолок суммарного объёма. Старые файлы вытесняются
	// раньше срока, если новый не помещается.
	MaxBytes int

	mu    sync.Mutex
	items map[string]*entry
	order []string
	total int
	now   func() time.Time
}

type entry struct {
	name        string
	contentType string
	data        []byte
	expires     time.Time
}

// Prefix — путь, под которым Memory отдаёт файлы.
const Prefix = "/files/"

// NewMemory создаёт хранилище в памяти.
func NewMemory(baseURL string, ttl time.Duration, maxBytes int) *Memory {
	return &Memory{
		BaseURL:  strings.TrimSuffix(baseURL, "/"),
		TTL:      ttl,
		MaxBytes: maxBytes,
		items:    make(map[string]*entry),
		now:      time.Now,
	}
}

// Save кладёт файл и возвращает ссылку на него.
func (m *Memory) Save(name, contentType string, data []byte) (Saved, error) {
	if m.MaxBytes > 0 && len(data) > m.MaxBytes {
		return Saved{}, fmt.Errorf("%w: %d байт при потолке %d", ErrTooLarge, len(data), m.MaxBytes)
	}

	token, err := randomToken()
	if err != nil {
		return Saved{}, err
	}
	now := m.now()
	base := stamped(safeName(name, contentType), now)
	e := &entry{name: base, contentType: contentType, data: data, expires: now.Add(m.TTL)}

	m.mu.Lock()
	m.evictLocked(now, len(data))
	m.items[token] = e
	m.order = append(m.order, token)
	m.total += len(data)
	m.mu.Unlock()

	return Saved{
		Location: m.BaseURL + Prefix + token + "/" + base,
		Name:     base,
		Size:     len(data),
		Expires:  e.expires,
	}, nil
}

// evictLocked выбрасывает просроченное и, если места всё равно мало,
// самые старые файлы.
func (m *Memory) evictLocked(now time.Time, incoming int) {
	kept := m.order[:0]
	for _, tok := range m.order {
		e, ok := m.items[tok]
		if !ok {
			continue
		}
		overflow := m.MaxBytes > 0 && m.total+incoming > m.MaxBytes
		if now.After(e.expires) || overflow {
			m.total -= len(e.data)
			delete(m.items, tok)
			continue
		}
		kept = append(kept, tok)
	}
	m.order = kept
}

// ServeHTTP отдаёт файл по ссылке вида /files/<токен>/<имя>.
func (m *Memory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, Prefix)
	token, _, _ := strings.Cut(rest, "/")

	m.mu.Lock()
	e, ok := m.items[token]
	if ok && m.now().After(e.expires) {
		m.total -= len(e.data)
		delete(m.items, token)
		ok = false
	}
	m.mu.Unlock()

	if !ok {
		http.Error(w, "файл не найден или ссылка истекла — запросите документ заново", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", e.contentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("inline", map[string]string{"filename": e.name}))
	// Ссылка — это право доступа. Кешировать её у посредников и
	// передавать в Referer незачем.
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(e.data)
}

// --- Общее ---

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("files: генерация токена: %w", err)
	}
	return hex.EncodeToString(b), nil
}

var unsafeChars = regexp.MustCompile(`[^\p{L}\p{N}._-]+`)

// safeName приводит имя к виду, безопасному и для файловой системы,
// и для URL, и дописывает расширение по типу, если его нет.
func safeName(name, contentType string) string {
	name = filepath.Base(strings.TrimSpace(name))
	name = unsafeChars.ReplaceAllString(name, "_")
	name = strings.Trim(name, "._")
	if name == "" {
		name = "document"
	}
	if filepath.Ext(name) == "" {
		name += extFor(contentType)
	}
	return name
}

func extFor(contentType string) string {
	ct, _, _ := mime.ParseMediaType(contentType)
	switch ct {
	case "application/pdf":
		return ".pdf"
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "text/plain":
		return ".txt"
	}
	return ".bin"
}

// stamped вставляет время перед расширением: labels.pdf →
// labels_2026-09-28_15-04-05.pdf.
func stamped(name string, t time.Time) string {
	ext := filepath.Ext(name)
	return strings.TrimSuffix(name, ext) + "_" + t.Format("2006-01-02_15-04-05") + ext
}
