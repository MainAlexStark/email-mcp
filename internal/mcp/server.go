// Package mcp — тонкий слой над официальным Go SDK протокола MCP.
//
// Здесь остались только две вещи: описание инструмента и способы отдать
// набор инструментов наружу — потоком newline-JSON (stdio) и
// обработчиком HTTP. Сам протокол — рукопожатие, согласование версий,
// форма ошибок, режим без состояния — держит
// github.com/modelcontextprotocol/go-sdk.
//
// Раньше на этом месте лежала собственная реализация JSON-RPC. Она
// позволяла собирать репозиторий без единой внешней зависимости, но
// платой было обещание самому догонять спецификацию, которая меняется
// несколько раз в год: версии протокола, требования к заголовкам,
// поведение stateless-режима. Догонять её вручную ради тридцати
// инструментов — не та работа, ради которой писался этот сервер.
//
// Граница пакета сохранена намеренно: internal/tools не знает ни про
// JSON-RPC, ни про типы SDK. Поэтому следующая смена версии протокола
// останавливается здесь и не расходится по всем инструментам.
package mcp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tool — один инструмент, доступный модели.
type Tool struct {
	Name        string
	Description string

	// InputSchema — JSON Schema аргументов. Модель видит именно её,
	// поэтому описание полей здесь важнее, чем кажется.
	InputSchema map[string]any

	// Handler получает сырые аргументы и возвращает текст результата.
	Handler func(ctx context.Context, args json.RawMessage) (string, error)
}

// Server — набор инструментов, который можно отдать любым из двух
// транспортов.
type Server struct {
	impl *sdk.Server

	// Порядок и имена ведём сами: SDK хранит инструменты в своей
	// структуре, а нам нужен стабильный порядок регистрации для
	// диагностики и проверка на повторное имя.
	mu    sync.RWMutex
	order []string
	known map[string]struct{}
}

// NewServer создаёт сервер с именем и версией.
func NewServer(name, version string) *Server {
	return &Server{
		impl: sdk.NewServer(
			&sdk.Implementation{Name: name, Version: version},
			&sdk.ServerOptions{
				// Список инструментов фиксируется на старте и больше не
				// меняется, поэтому listChanged не объявляем: клиенту
				// незачем ждать уведомлений, которых не будет. Заодно
				// не объявляем и логирование, которого сервер не ведёт.
				Capabilities: &sdk.ServerCapabilities{Tools: &sdk.ToolCapabilities{}},
			},
		),
		known: make(map[string]struct{}),
	}
}

// Register добавляет инструмент. Повторная регистрация имени — ошибка
// программиста, поэтому паникуем на старте, а не молча перетираем.
func (s *Server) Register(t Tool) {
	s.mu.Lock()
	if _, dup := s.known[t.Name]; dup {
		s.mu.Unlock()
		panic("mcp: инструмент уже зарегистрирован: " + t.Name)
	}
	s.known[t.Name] = struct{}{}
	s.order = append(s.order, t.Name)
	s.mu.Unlock()

	schema := t.InputSchema
	if schema == nil {
		schema = map[string]any{"type": "object"}
	}

	handler := t.Handler

	// Регистрируем низкоуровневым способом: аргументы доходят до
	// инструмента сырыми и разбираются им самим. Типизированный AddTool
	// из SDK проверял бы их по схеме сам, но потребовал бы описать
	// каждый инструмент структурой Go — это отдельная работа, и делать
	// её заодно со сменой каркаса значило бы менять две вещи разом.
	s.impl.AddTool(&sdk.Tool{
		Name:        t.Name,
		Description: t.Description,
		InputSchema: schema,
	}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		text, err := handler(ctx, req.Params.Arguments)
		if err != nil {
			// Ошибка инструмента возвращается как результат с isError,
			// а не как ошибка протокола: модель должна её прочитать
			// и попробовать исправиться, а не считать сервер сломанным.
			return &sdk.CallToolResult{
				Content: []sdk.Content{&sdk.TextContent{Text: err.Error()}},
				IsError: true,
			}, nil
		}
		return &sdk.CallToolResult{
			Content: []sdk.Content{&sdk.TextContent{Text: text}},
		}, nil
	})
}

// ToolNames перечисляет инструменты в порядке регистрации.
func (s *Server) ToolNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.order...)
}

// Serve обслуживает поток newline-JSON: так с сервером разговаривает
// Claude, запустивший его подпроцессом.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	return s.impl.Run(ctx, &sdk.IOTransport{
		Reader: io.NopCloser(in),
		Writer: nopCloser{out},
	})
}

// StreamableOptions — настройки сетевого обработчика.
type StreamableOptions struct {
	Logger *slog.Logger

	// MaxRequestBytes — потолок размера тела запроса. 0 оставляет
	// значение SDK по умолчанию.
	MaxRequestBytes int64
}

// StreamableHandler возвращает обработчик MCP поверх Streamable HTTP.
//
// Режим без состояния: сервер не выдаёт Mcp-Session-Id и не требует
// его, каждый запрос самодостаточен. Так было и в собственной
// реализации, и причина та же — такой сервер переживает перезапуск
// процесса и не ломается за балансировщиком.
//
// Авторизация, проверка Origin и права подключения остаются снаружи,
// в internal/httpx: SDK ничего не знает ни про токены, ни про то, кому
// разрешена запись.
func (s *Server) StreamableHandler(opts StreamableOptions) http.Handler {
	return sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return s.impl },
		&sdk.StreamableHTTPOptions{
			Stateless: true,

			// Ответ отдаётся обычным JSON, а не потоком событий: сервер
			// ничего не шлёт по своей инициативе, а с JSON проще жить
			// автоматизации, которая ходит сюда со статическим токеном.
			JSONResponse: true,

			MaxRequestBodyBytes: opts.MaxRequestBytes,
			Logger:              opts.Logger,

			// Встроенную в SDK защиту от DNS rebinding приходится
			// выключить: она отклоняет запрос, пришедший на localhost
			// с внешним Host, а это ровно штатная схема развёртывания —
			// Caddy на 443 и сервер на 127.0.0.1:8571. Проверка Origin
			// стоит в internal/httpx и работает для всех запросов.
			DisableLocalhostProtection: true,
		})
}

// nopCloser добавляет Close писателю: транспорт SDK принимает
// io.WriteCloser, а закрывать stdout или буфер теста незачем.
type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }
