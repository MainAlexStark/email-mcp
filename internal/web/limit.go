package web

import (
	"crypto/subtle"
	"sync"
	"time"
)

// ipLimiter — ведро токенов на адрес: burst попыток сразу, дальше одна
// в every. Живёт в памяти: сервис один, а после перезапуска начать
// счёт заново не страшно.
type ipLimiter struct {
	mu      sync.Mutex
	burst   float64
	every   time.Duration
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	seen   time.Time
}

func newIPLimiter(burst int, every time.Duration) *ipLimiter {
	return &ipLimiter{burst: float64(burst), every: every, buckets: map[string]*bucket{}, lastGC: time.Now()}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if now.Sub(l.lastGC) > 10*time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.seen) > time.Hour {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}

	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{tokens: l.burst, seen: now}
		l.buckets[ip] = b
	}
	b.tokens += float64(now.Sub(b.seen)) / float64(l.every)
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.seen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func secureEqual(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
