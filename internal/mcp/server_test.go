package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/MainAlexStark/email-mcp/internal/mcp"
	"github.com/MainAlexStark/email-mcp/internal/mcptest"
)

// echoSchema объявлен отдельно, чтобы тест мог сверить, что схема
// доезжает до клиента ровно такой, какой её написали: модель принимает
// решения по ней, и любая правка по дороге меняет её поведение.
var echoSchema = map[string]any{
	"type":       "object",
	"properties": map[string]any{"text": map[string]any{"type": "string"}},
	"required":   []any{"text"},
}

func newTestServer() *mcp.Server {
	s := mcp.NewServer("test", "0.0.1")
	s.Register(mcp.Tool{
		Name:        "echo",
		Description: "возвращает переданный текст",
		InputSchema: echoSchema,
		Handler: func(_ context.Context, args json.RawMessage) (string, error) {
			var a struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			if a.Text == "" {
				return "", errors.New("text обязателен")
			}
			return a.Text, nil
		},
	})
	return s
}

func start(t *testing.T) *mcptest.Session {
	t.Helper()

	sess, err := mcptest.Start(newTestServer())
	if err != nil {
		t.Fatalf("сессия не поднялась: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func TestHandshakeReportsServerInfo(t *testing.T) {
	sess := start(t)

	info := sess.ServerInfo()
	if info.Name != "test" || info.Version != "0.0.1" {
		t.Errorf("serverInfo = %+v", info)
	}
	if info.ProtocolVersion == "" {
		t.Error("сервер не назвал версию протокола")
	}
}

func TestToolsListShowsSchemaUnchanged(t *testing.T) {
	sess := start(t)

	list, err := sess.Tools()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "echo" {
		t.Fatalf("tools/list вернул %+v", list)
	}

	// Схема проходит через протокол JSON, поэтому сверяем с тем, во что
	// превращается исходная карта после разбора: важно, что не потеряны
	// поля, а не то, каким типом представлено число.
	var want map[string]any
	raw, _ := json.Marshal(echoSchema)
	_ = json.Unmarshal(raw, &want)

	if !reflect.DeepEqual(list[0].InputSchema, want) {
		t.Errorf("схема доехала изменённой:\nполучено %v\nожидалось %v", list[0].InputSchema, want)
	}
}

func TestToolsCall(t *testing.T) {
	sess := start(t)

	res, err := sess.Call("echo", map[string]any{"text": "привет"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError || res.Text != "привет" {
		t.Errorf("неожиданный ответ: %+v", res)
	}
}

func TestToolErrorIsResultNotProtocolError(t *testing.T) {
	// Ошибка инструмента должна доходить до модели как текст,
	// иначе она не сможет исправить аргументы.
	sess := start(t)

	res, err := sess.Call("echo", map[string]any{})
	if err != nil {
		t.Fatalf("ошибка инструмента не должна быть ошибкой протокола: %v", err)
	}
	if !res.IsError {
		t.Errorf("ожидался isError=true, получено %+v", res)
	}
	if res.Text == "" {
		t.Error("причина отказа должна доезжать текстом")
	}
}

func TestUnknownToolIsProtocolError(t *testing.T) {
	sess := start(t)

	_, rpcErr, err := sess.Request("tools/call", map[string]any{
		"name":      "нет-такого",
		"arguments": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rpcErr == nil {
		t.Fatal("неизвестный инструмент должен давать ошибку протокола")
	}
}

func TestUnknownMethod(t *testing.T) {
	sess := start(t)

	_, rpcErr, err := sess.Request("nope", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rpcErr == nil {
		t.Fatal("неизвестный метод должен давать ошибку протокола")
	}
}

func TestNotificationGetsNoResponse(t *testing.T) {
	sess := start(t)

	if err := sess.Notify("notifications/cancelled", map[string]any{
		"requestId": 999,
		"reason":    "тест",
	}); err != nil {
		t.Fatal(err)
	}

	// Если бы сервер ответил на уведомление, лишнее сообщение попало бы
	// в поток и следующий запрос получил бы чужой идентификатор.
	if _, _, err := sess.Request("ping", map[string]any{}); err != nil {
		t.Fatalf("после уведомления сессия должна работать как обычно: %v", err)
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("повторная регистрация имени должна паниковать на старте")
		}
	}()
	s := newTestServer()
	s.Register(mcp.Tool{Name: "echo"})
}
