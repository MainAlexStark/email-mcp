package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	xproxy "golang.org/x/net/proxy"
)

// Client — операции с одним ящиком.
type Client struct {
	acc  Account
	opts options
}

type options struct {
	tlsConfig  *tls.Config
	publicOnly bool
	proxy      *url.URL
	proxyDial  xproxy.Dialer
}

// Option настраивает клиента.
type Option func(*options)

// WithTLSConfig подменяет настройки TLS (в тестах — доверие к
// самоподписанному сертификату).
func WithTLSConfig(c *tls.Config) Option { return func(o *options) { o.tlsConfig = c } }

// WithPublicOnly запрещает подключаться к внутренним адресам.
//
// В сервисе адрес сервера вводит пользователь. Без запрета он мог бы
// указать postgres:5432, 127.0.0.1 или 169.254.169.254 и превратить
// проверку ящика в сканер внутренней сети сервера: по тексту ошибки
// видно, открыт ли порт. Проверка стоит на уже разрешённом адресе
// (Control у dialer), поэтому DNS, который отдаёт внутренний адрес,
// её не обходит.
func WithPublicOnly() Option { return func(o *options) { o.publicOnly = true } }

// WithProxy направляет IMAP и SMTP через SOCKS5-прокси.
//
// Нужен, когда сервер стоит там, откуда почтовый провайдер недоступен
// (Gmail из России: порты 465/587 не отвечают). Формат —
// socks5://[user:pass@]host:port; имя почтового сервера уходит прокси
// как есть, и DNS разрешает он, а не локальная машина.
//
// Прокси задаёт оператор, а не пользователь сервиса, поэтому проверка
// WithPublicOnly к нему не применяется (он может стоять на 127.0.0.1).
// Целевой адрес при этом разрешается на стороне прокси, и «внутренней
// сети сервиса» этот трафик не касается.
func WithProxy(rawURL string) (Option, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("не разобрать адрес прокси: %w", err)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("прокси %q: поддерживается только socks5://", u.Redacted())
	}
	if u.Host == "" {
		return nil, fmt.Errorf("прокси %q: не указан адрес", u.Redacted())
	}
	var auth *xproxy.Auth
	if u.User != nil {
		pw, _ := u.User.Password()
		auth = &xproxy.Auth{User: u.User.Username(), Password: pw}
	}
	d, err := xproxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("прокси %q: %w", u.Redacted(), err)
	}
	return func(o *options) { o.proxy, o.proxyDial = u, d }, nil
}

// New создаёт клиента ящика.
func New(acc Account, opts ...Option) *Client {
	c := &Client{acc: acc}
	for _, o := range opts {
		o(&c.opts)
	}
	return c
}

// Account — описание ящика (без пароля наружу не отдавать).
func (c *Client) Account() Account { return c.acc }

// ErrPrivateAddress — адрес сервера внутренний, а они запрещены.
var ErrPrivateAddress = errors.New("адрес сервера ведёт во внутреннюю сеть — такие адреса сервис не открывает")

func (c *Client) dialer() *net.Dialer {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if c.opts.publicOnly {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return ErrPrivateAddress
			}
			a := ap.Addr().Unmap()
			if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
				a.IsUnspecified() || a.IsMulticast() || isCGNAT(a) {
				return ErrPrivateAddress
			}
			return nil
		}
	}
	return d
}

// isCGNAT — 100.64.0.0/10: внутренние адреса облаков и Tailscale.
func isCGNAT(a netip.Addr) bool {
	return a.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

func (c *Client) tlsConfig(host string) *tls.Config {
	if c.opts.tlsConfig != nil {
		cfg := c.opts.tlsConfig.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		return cfg
	}
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
}

// dial открывает соединение с учётом контекста и режима защиты.
func (c *Client) dial(ctx context.Context, srv Server) (net.Conn, error) {
	var conn net.Conn
	var err error
	if c.opts.proxyDial != nil {
		if cd, ok := c.opts.proxyDial.(xproxy.ContextDialer); ok {
			conn, err = cd.DialContext(ctx, "tcp", srv.Addr())
		} else {
			conn, err = c.opts.proxyDial.Dial("tcp", srv.Addr())
		}
	} else {
		conn, err = c.dialer().DialContext(ctx, "tcp", srv.Addr())
	}
	if err != nil {
		if errors.Is(err, ErrPrivateAddress) {
			return nil, &Error{Kind: KindInput, Msg: ErrPrivateAddress.Error(), Host: srv.Host}
		}
		return nil, classify(err, srv.Host, stageConnect)
	}
	if srv.Security == SecurityTLS {
		tc := tls.Client(conn, c.tlsConfig(srv.Host))
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, classify(err, srv.Host, stageConnect)
		}
		return tc, nil
	}
	return conn, nil
}

// imapSession открывает IMAP-сессию, выполняет fn и закрывает её.
//
// Контекст соблюдается двумя способами сразу: срок операции ставится
// дедлайном сокета (иначе зависший сервер держал бы вызов вечно),
// а отмена контекста закрывает соединение (иначе ушедший клиент MCP
// оставлял бы за собой висящую сессию).
func (c *Client) imapSession(ctx context.Context, fn func(*imapclient.Client) error) (err error) {
	ctx, cancel := context.WithTimeout(ctx, c.acc.timeout())
	defer cancel()

	srv := c.acc.IMAP
	conn, err := c.dial(ctx, srv)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	opts := &imapclient.Options{TLSConfig: c.tlsConfig(srv.Host)}
	var cl *imapclient.Client
	if srv.Security == SecurityStartTLS {
		cl, err = imapclient.NewStartTLS(conn, opts)
		if err != nil {
			conn.Close()
			return classify(err, srv.Host, stageConnect)
		}
	} else {
		cl = imapclient.New(conn, opts)
	}

	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer func() {
		// Logout вежлив, но не обязателен: если сервер не ответил,
		// соединение закрываем всё равно.
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_ = cl.Logout().Wait()
		_ = cl.Close()
	}()

	if err := cl.WaitGreeting(); err != nil {
		return classify(ctxErr(ctx, err), srv.Host, stageConnect)
	}
	if err := cl.Login(c.acc.Username, c.acc.Password).Wait(); err != nil {
		return classify(ctxErr(ctx, err), srv.Host, stageLogin)
	}
	if err := fn(cl); err != nil {
		return classify(ctxErr(ctx, err), srv.Host, "операция с ящиком")
	}
	return nil
}

// ctxErr — если соединение закрыли мы сами по контексту, честнее
// сообщить о таймауте, чем о «use of closed network connection».
func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w (%v)", ctx.Err(), err)
	}
	return err
}
