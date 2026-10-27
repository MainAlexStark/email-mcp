# Сборка
FROM golang:1.25-alpine AS build

WORKDIR /src

# Зависимости отдельным слоем: он переживает правки кода и не тянет
# модули заново на каждую сборку.
COPY go.mod go.sum ./
RUN go mod download || true

COPY . .

ARG VERSION=docker

# -mod=mod: если в go.sum не хватает записей (новую зависимость
# добавили, а `go mod tidy` не прогнали), сборка дотянет их сама,
# сверив контрольные суммы с sum.golang.org, вместо того чтобы упасть
# посреди обновления сервера. Правильное состояние — полный go.sum
# в репозитории (make tidy); это только страховка.
RUN CGO_ENABLED=0 go build -mod=mod -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/email-mcp ./cmd/email-mcp


# Запуск
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/email-mcp /email-mcp

# Состояния на диске у сервера нет: пользователи, ящики и токены
# живут в PostgreSQL. Поэтому ни томов, ни прав на каталоги.
USER nonroot:nonroot

EXPOSE 8572

ENTRYPOINT ["/email-mcp"]
CMD ["--http", "0.0.0.0:8572"]
