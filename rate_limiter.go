package tlspermissionpolicy

import (
	"fmt"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

// RateLimit defines a sliding-window rate limit: at most Limit approvals per Duration.
type RateLimit struct {
	Limit    int            `json:"limit"`
	Duration caddy.Duration `json:"duration"`
}

// rateLimitState holds in-memory sliding-window counters for global and per-domain rate limits.
type rateLimitState struct {
	mu             sync.Mutex
	global         windowCounter
	domains        map[string]*windowCounter
	globalLimit    *RateLimit
	perDomainLimit *RateLimit
	now            func() time.Time
}

// windowCounter implements a two-bucket sliding-window counter approximation.
// It tracks the previous and current fixed-window counts, and interpolates
// to produce an estimate of approvals within the past duration.
type windowCounter struct {
	prevCount   int
	currCount   int
	windowStart time.Time
}

// advance rotates the counter buckets if the current window has elapsed.
func (w *windowCounter) advance(now time.Time, d time.Duration) {
	if w.windowStart.IsZero() {
		w.windowStart = now
		return
	}
	elapsed := now.Sub(w.windowStart)
	if elapsed < d {
		return
	}
	n := int(elapsed / d)
	if n >= 2 {
		w.prevCount = 0
		w.currCount = 0
	} else {
		w.prevCount = w.currCount
		w.currCount = 0
	}
	w.windowStart = w.windowStart.Add(time.Duration(n) * d)
}

// estimate returns the approximate number of approvals in the sliding window ending at now.
func (w *windowCounter) estimate(now time.Time, d time.Duration) float64 {
	w.advance(now, d)
	elapsed := now.Sub(w.windowStart)
	weight := 1.0 - float64(elapsed)/float64(d)
	return float64(w.prevCount)*weight + float64(w.currCount)
}

// checkGlobal returns an error if the global rate limit is exceeded.
func (s *rateLimitState) checkGlobal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	d := time.Duration(s.globalLimit.Duration)
	if s.global.estimate(now, d) >= float64(s.globalLimit.Limit) {
		return fmt.Errorf("%w: global certificate rate limit exceeded", caddytls.ErrPermissionDenied)
	}
	return nil
}

// recordGlobal records an approved certificate in the global counter.
func (s *rateLimitState) recordGlobal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.global.advance(now, time.Duration(s.globalLimit.Duration))
	s.global.currCount++
}

// checkDomain returns an error if the per-domain rate limit is exceeded for the given domain.
// Expired domain entries are evicted lazily to keep memory usage minimal.
func (s *rateLimitState) checkDomain(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	d := time.Duration(s.perDomainLimit.Duration)
	w, ok := s.domains[domain]
	if !ok {
		return nil
	}
	est := w.estimate(now, d)
	if est <= 0 {
		delete(s.domains, domain)
		return nil
	}
	if est >= float64(s.perDomainLimit.Limit) {
		return fmt.Errorf("%w: per-domain certificate rate limit exceeded for %s", caddytls.ErrPermissionDenied, domain)
	}
	return nil
}

// recordDomain records an approved certificate for the given domain.
func (s *rateLimitState) recordDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	d := time.Duration(s.perDomainLimit.Duration)
	w, ok := s.domains[domain]
	if !ok {
		w = &windowCounter{windowStart: now}
		s.domains[domain] = w
	}
	w.advance(now, d)
	w.currCount++
}
