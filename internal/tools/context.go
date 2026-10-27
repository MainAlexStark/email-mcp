package tools

import (
	"context"

	"github.com/MainAlexStark/email-mcp/mail"
)

// Права — свойство ЗАПРОСА, а не процесса.
//
// Пока сервер работает по stdio, это одно и то же: его запускает сам
// пользователь на своей машине, и переменной окружения хватает. Как
// только тот же сервер выставлен в интернет, разные обращения приходят
// с разными правами — с телефона только чтение, с рабочей машины с
// отправкой, — и глобальная настройка перестаёт что-либо значить.
//
// Поэтому Safety кладётся в контекст запроса на входе (HTTP-транспорт
// делает это после проверки токена), а инструменты читают её оттуда.
// Настройка процесса остаётся только запасным значением для stdio.

type safetyKey struct{}

// WithSafety кладёт права запроса в контекст.
func WithSafety(ctx context.Context, s Safety) context.Context {
	return context.WithValue(ctx, safetyKey{}, s)
}

// SafetyFrom достаёт права запроса.
//
// Второе значение — были ли права заданы явно. Вызывающий код обязан
// его проверять: молча подставить разрешающие настройки, когда в
// контексте ничего нет, — ровно тот способ, которым такие проверки
// и обходят.
func SafetyFrom(ctx context.Context) (Safety, bool) {
	s, ok := ctx.Value(safetyKey{}).(Safety)
	return s, ok
}

// safetyFor возвращает права для текущего запроса: из контекста, если
// транспорт их проставил, иначе настройки процесса.
func (r *Registry) safetyFor(ctx context.Context) Safety {
	if s, ok := SafetyFrom(ctx); ok {
		return s
	}
	return r.safety
}

// Ящики — тоже свойство запроса.
//
// В stdio они заданы окружением и известны на старте. В сервисе у
// каждого подключения свои: транспорт после проверки токена кладёт
// в контекст ящики именно этого пользователя (все или один, как
// выбрано на экране согласия).

type accountsKey struct{}

// WithAccounts кладёт ящики запроса в контекст.
func WithAccounts(ctx context.Context, list []mail.Account) context.Context {
	return context.WithValue(ctx, accountsKey{}, list)
}

// accountsFor — ящики текущего запроса; ok=false — источник не задан
// вовсе (ни контекст, ни реестр), и это ошибка сборки, а не «ящиков нет».
func (r *Registry) accountsFor(ctx context.Context) ([]mail.Account, bool) {
	if list, ok := ctx.Value(accountsKey{}).([]mail.Account); ok {
		return list, true
	}
	if r.accounts != nil {
		return r.accounts, true
	}
	return nil, false
}

// CallHook узнаёт о каждом вызове инструмента — для учёта вызовов.
type CallHook func(tool string, failed bool)

type hookKey struct{}

// WithCallHook подвешивает к запросу наблюдателя за вызовами.
func WithCallHook(ctx context.Context, h CallHook) context.Context {
	return context.WithValue(ctx, hookKey{}, h)
}
