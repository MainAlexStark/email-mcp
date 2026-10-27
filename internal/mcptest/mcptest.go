// Package mcptest — клиентская сторона MCP для тестов.
//
// Инструменты проверяются через настоящий протокол: рукопожатие,
// tools/call, разбор ответа. Дёргать обработчик напрямую было бы
// проще, но тогда из-под теста выпадает ровно тот слой, где обычно и
// живут ошибки, — форма аргументов и форма ответа.
//
// Клиент здесь свой, а не из SDK, и это осознанно: тесты должны
// ломаться, когда ломается провод, а не когда обе стороны одинаково
// неправильно понимают спецификацию.
package mcptest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/MainAlexStark/email-mcp/internal/mcp"
)

// ProtocolVersion — версия, которую предлагает тестовый клиент.
const ProtocolVersion = "2025-06-18"

// Session — открытая сессия с сервером.
type Session struct {
	in     *io.PipeWriter
	out    *io.PipeReader
	enc    *json.Encoder
	dec    *json.Decoder
	cancel context.CancelFunc
	done   chan error

	nextID int
	info   ServerInfo
}

// ServerInfo — то, что сервер рассказал о себе при рукопожатии.
type ServerInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ProtocolVersion string `json:"-"`
}

// Result — то, что вернул инструмент.
type Result struct {
	Text    string
	IsError bool
}

// RPCError — ошибка уровня протокола (не ошибка инструмента).
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("jsonrpc %d: %s", e.Code, e.Message)
}

// ToolInfo — описание инструмента из tools/list, ровно как его видит
// модель.
type ToolInfo struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Start поднимает сервер на паре каналов и проходит рукопожатие.
//
// Рукопожатие не пропускается: сессия без него — это не то, с чем
// работают настоящие клиенты, и проверять на ней нечего.
func Start(s *mcp.Server) (*Session, error) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())

	sess := &Session{
		in:     inW,
		out:    outR,
		enc:    json.NewEncoder(inW),
		dec:    json.NewDecoder(outR),
		cancel: cancel,
		done:   make(chan error, 1),
	}

	go func() {
		err := s.Serve(ctx, inR, outW)
		// Закрываем сторону чтения, чтобы клиент, ждущий ответа,
		// не завис, если сервер закончил раньше.
		_ = outW.Close()
		sess.done <- err
	}()

	raw, rpcErr, err := sess.Request("initialize", map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcptest", "version": "0"},
	})
	switch {
	case err != nil:
		sess.Close()
		return nil, err
	case rpcErr != nil:
		sess.Close()
		return nil, rpcErr
	}

	var initResult struct {
		ProtocolVersion string     `json:"protocolVersion"`
		ServerInfo      ServerInfo `json:"serverInfo"`
	}
	if err := json.Unmarshal(raw, &initResult); err != nil {
		sess.Close()
		return nil, fmt.Errorf("ответ на initialize не разобрался: %w", err)
	}
	sess.info = initResult.ServerInfo
	sess.info.ProtocolVersion = initResult.ProtocolVersion

	if err := sess.Notify("notifications/initialized", map[string]any{}); err != nil {
		sess.Close()
		return nil, err
	}
	return sess, nil
}

// ServerInfo возвращает данные из рукопожатия.
func (s *Session) ServerInfo() ServerInfo { return s.info }

// Request отправляет запрос и ждёт ответ.
//
// Ошибка протокола возвращается вторым значением, а не третьим: для
// части тестов она и есть ожидаемый результат.
func (s *Session) Request(method string, params any) (json.RawMessage, *RPCError, error) {
	s.nextID++
	id := s.nextID

	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	if err := s.enc.Encode(req); err != nil {
		return nil, nil, fmt.Errorf("не отправить %s: %w", method, err)
	}

	var resp struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *RPCError       `json:"error"`
	}
	if err := s.dec.Decode(&resp); err != nil {
		return nil, nil, fmt.Errorf("не прочитать ответ на %s: %w", method, err)
	}

	// Проверка идентификатора здесь не формальность: она ловит лишние
	// сообщения от сервера — например, ответ на уведомление, которого
	// быть не должно.
	if resp.ID != id {
		return nil, nil, fmt.Errorf("ответ не на тот запрос: ожидался id=%d, получен id=%d", id, resp.ID)
	}
	return resp.Result, resp.Error, nil
}

// Notify отправляет уведомление — сообщение без идентификатора,
// на которое ответа не ждут.
func (s *Session) Notify(method string, params any) error {
	req := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		req["params"] = params
	}
	if err := s.enc.Encode(req); err != nil {
		return fmt.Errorf("не отправить уведомление %s: %w", method, err)
	}
	return nil
}

// Tools возвращает список инструментов так, как его видит клиент.
func (s *Session) Tools() ([]ToolInfo, error) {
	raw, rpcErr, err := s.Request("tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	if rpcErr != nil {
		return nil, rpcErr
	}

	var result struct {
		Tools []ToolInfo `json:"tools"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("tools/list не разобрался: %w", err)
	}
	return result.Tools, nil
}

// Call вызывает инструмент и возвращает его текстовый ответ.
func (s *Session) Call(name string, args any) (Result, error) {
	raw, rpcErr, err := s.Request("tools/call", map[string]any{
		"name":      name,
		"arguments": args,
	})
	if err != nil {
		return Result{}, err
	}
	if rpcErr != nil {
		return Result{}, rpcErr
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return Result{}, fmt.Errorf("результат вызова %s не разобрался: %w", name, err)
	}
	if len(result.Content) == 0 {
		return Result{}, fmt.Errorf("инструмент %s вернул пустой ответ", name)
	}
	return Result{Text: result.Content[0].Text, IsError: result.IsError}, nil
}

// Close закрывает сессию и дожидается остановки сервера.
func (s *Session) Close() error {
	_ = s.in.Close()
	s.cancel()
	err := <-s.done
	_ = s.out.Close()
	return err
}
