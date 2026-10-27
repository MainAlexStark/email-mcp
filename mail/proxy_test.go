package mail_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/MainAlexStark/email-mcp/mail"
	"github.com/MainAlexStark/email-mcp/mail/mailtest"
)

// socks5 — минимальный SOCKS5-сервер без авторизации: достаточно, чтобы
// убедиться, что трафик ящика идёт именно через прокси.
func socks5(t *testing.T, hits *atomic.Int32) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 262)
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				io.ReadFull(c, buf[:int(buf[1])])
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, buf[:4]); err != nil {
					return
				}
				var host string
				switch buf[3] {
				case 1:
					io.ReadFull(c, buf[:4])
					host = net.IP(buf[:4]).String()
				case 3:
					io.ReadFull(c, buf[:1])
					n := int(buf[0])
					io.ReadFull(c, buf[:n])
					host = string(buf[:n])
				default:
					return
				}
				io.ReadFull(c, buf[:2])
				port := int(buf[0])<<8 | int(buf[1])
				up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				hits.Add(1)
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	return "socks5://" + ln.Addr().String()
}

func TestProxyIsUsed(t *testing.T) {
	var hits atomic.Int32
	srv := mailtest.Start(t)
	opt, err := mail.WithProxy(socks5(t, &hits))
	if err != nil {
		t.Fatal(err)
	}
	// WithPublicOnly + прокси на loopback: прокси задаёт оператор, это допустимо.
	c := mail.New(srv.Account("work"), mail.WithPublicOnly(), opt)
	if res, err := c.VerifyIMAP(context.Background()); err != nil || !res.OK {
		t.Fatalf("verify via proxy: %v %+v", err, res)
	}
	if hits.Load() == 0 {
		t.Fatal("соединение прошло мимо прокси")
	}
}

func TestProxyBadURL(t *testing.T) {
	for _, u := range []string{"http://x:1", "socks5://", "://bad"} {
		if _, err := mail.WithProxy(u); err == nil {
			t.Errorf("%q: ожидалась ошибка", u)
		}
	}
}

func TestProxyDown(t *testing.T) {
	srv := mailtest.Start(t)
	opt, _ := mail.WithProxy("socks5://127.0.0.1:1")
	c := mail.New(srv.Account("work"), opt)
	if _, err := c.VerifyIMAP(context.Background()); err == nil {
		t.Fatal("при недоступном прокси соединение не должно идти напрямую")
	}
}
