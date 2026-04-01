// Copyright 2026 Pieter Berkel
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tlspermissionpolicy

import (
	"errors"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

// ---- windowCounter.advance ----

func TestWindowCounterAdvance(t *testing.T) {
	t.Run("initializes windowStart when zero", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		w := windowCounter{}

		w.advance(now, time.Minute)

		if !w.windowStart.Equal(now) {
			t.Errorf("expected windowStart=%v, got %v", now, w.windowStart)
		}
		if w.prevCount != 0 || w.currCount != 0 {
			t.Errorf("expected counts to remain 0, got prev=%d curr=%d", w.prevCount, w.currCount)
		}
	})

	t.Run("no-op when elapsed is less than window duration", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		w := windowCounter{prevCount: 3, currCount: 5, windowStart: start}

		w.advance(start.Add(30*time.Second), time.Minute)

		if w.prevCount != 3 || w.currCount != 5 {
			t.Errorf("expected counts unchanged, got prev=%d curr=%d", w.prevCount, w.currCount)
		}
		if !w.windowStart.Equal(start) {
			t.Errorf("expected windowStart unchanged, got %v", w.windowStart)
		}
	})

	t.Run("rotates one bucket when exactly one window has elapsed", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		w := windowCounter{prevCount: 3, currCount: 7, windowStart: start}

		w.advance(start.Add(time.Minute), time.Minute)

		if w.prevCount != 7 {
			t.Errorf("expected prevCount=7, got %d", w.prevCount)
		}
		if w.currCount != 0 {
			t.Errorf("expected currCount=0, got %d", w.currCount)
		}
		if !w.windowStart.Equal(start.Add(time.Minute)) {
			t.Errorf("expected windowStart=%v, got %v", start.Add(time.Minute), w.windowStart)
		}
	})

	t.Run("rotates one bucket when slightly more than one window has elapsed", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		w := windowCounter{prevCount: 3, currCount: 7, windowStart: start}

		w.advance(start.Add(time.Minute+10*time.Second), time.Minute)

		if w.prevCount != 7 || w.currCount != 0 {
			t.Errorf("expected prev=7 curr=0, got prev=%d curr=%d", w.prevCount, w.currCount)
		}
		if !w.windowStart.Equal(start.Add(time.Minute)) {
			t.Errorf("expected windowStart=%v, got %v", start.Add(time.Minute), w.windowStart)
		}
	})

	t.Run("clears both buckets when two windows have elapsed", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		w := windowCounter{prevCount: 3, currCount: 7, windowStart: start}

		w.advance(start.Add(2*time.Minute), time.Minute)

		if w.prevCount != 0 || w.currCount != 0 {
			t.Errorf("expected both counts 0, got prev=%d curr=%d", w.prevCount, w.currCount)
		}
		if !w.windowStart.Equal(start.Add(2 * time.Minute)) {
			t.Errorf("expected windowStart=%v, got %v", start.Add(2*time.Minute), w.windowStart)
		}
	})

	t.Run("clears both buckets when more than two windows have elapsed", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		w := windowCounter{prevCount: 3, currCount: 7, windowStart: start}

		w.advance(start.Add(10*time.Minute), time.Minute)

		if w.prevCount != 0 || w.currCount != 0 {
			t.Errorf("expected both counts 0, got prev=%d curr=%d", w.prevCount, w.currCount)
		}
	})
}

// ---- windowCounter.estimate ----

func TestWindowCounterEstimate(t *testing.T) {
	t.Run("returns zero for fresh counter", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		w := windowCounter{}

		if est := w.estimate(now, time.Minute); est != 0 {
			t.Errorf("expected 0, got %f", est)
		}
	})

	t.Run("returns full count at start of window (weight=1.0)", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		// elapsed=0: weight = 1 - 0/d = 1.0
		// estimate = prevCount*1.0 + currCount = 4 + 3 = 7
		w := windowCounter{prevCount: 4, currCount: 3, windowStart: start}

		if est := w.estimate(start, time.Minute); est != 7.0 {
			t.Errorf("expected 7.0, got %f", est)
		}
	})

	t.Run("interpolates correctly at mid-window (weight=0.5)", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		// elapsed=30s, d=1m: weight = 1 - 0.5 = 0.5
		// estimate = 4*0.5 + 3 = 5.0
		w := windowCounter{prevCount: 4, currCount: 3, windowStart: start}

		if est := w.estimate(start.Add(30*time.Second), time.Minute); est != 5.0 {
			t.Errorf("expected 5.0, got %f", est)
		}
	})

	t.Run("uses only currCount as prev bucket decays at window boundary", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		// At elapsed=d, advance rotates: prev=currCount=3, curr=0, windowStart=start+d
		// Then elapsed=0 in new window, weight=1.0
		// estimate = 3*1.0 + 0 = 3.0
		w := windowCounter{prevCount: 4, currCount: 3, windowStart: start}

		if est := w.estimate(start.Add(time.Minute), time.Minute); est != 3.0 {
			t.Errorf("expected 3.0, got %f", est)
		}
	})

	t.Run("returns zero after two full windows", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		w := windowCounter{prevCount: 4, currCount: 3, windowStart: start}

		if est := w.estimate(start.Add(2*time.Minute), time.Minute); est != 0 {
			t.Errorf("expected 0, got %f", est)
		}
	})
}

// ---- rateLimitState global ----

func TestRateLimitStateGlobal(t *testing.T) {
	t.Run("allows requests below the limit", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		rl := &rateLimitState{
			globalLimit: &RateLimit{Limit: 3, Duration: caddy.Duration(time.Minute)},
			domains:     make(map[string]*windowCounter),
			now:         func() time.Time { return now },
		}

		rl.recordGlobal()
		rl.recordGlobal()

		if err := rl.checkGlobal(); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("denies at the limit", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		rl := &rateLimitState{
			globalLimit: &RateLimit{Limit: 2, Duration: caddy.Duration(time.Minute)},
			domains:     make(map[string]*windowCounter),
			now:         func() time.Time { return now },
		}

		rl.recordGlobal()
		rl.recordGlobal()

		err := rl.checkGlobal()
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("wraps error as ErrPermissionDenied", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		rl := &rateLimitState{
			globalLimit: &RateLimit{Limit: 1, Duration: caddy.Duration(time.Minute)},
			domains:     make(map[string]*windowCounter),
			now:         func() time.Time { return now },
		}

		rl.recordGlobal()

		err := rl.checkGlobal()
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected ErrPermissionDenied in error chain, got %v", err)
		}
	})

	t.Run("allows again after two full windows have elapsed", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		current := now
		rl := &rateLimitState{
			globalLimit: &RateLimit{Limit: 1, Duration: caddy.Duration(time.Minute)},
			domains:     make(map[string]*windowCounter),
			now:         func() time.Time { return current },
		}

		rl.recordGlobal()

		if err := rl.checkGlobal(); !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected denial before reset, got %v", err)
		}

		current = now.Add(2 * time.Minute)

		if err := rl.checkGlobal(); err != nil {
			t.Fatalf("expected allow after window reset, got %v", err)
		}
	})

	t.Run("recordGlobal increments counter", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		rl := &rateLimitState{
			globalLimit: &RateLimit{Limit: 10, Duration: caddy.Duration(time.Minute)},
			domains:     make(map[string]*windowCounter),
			now:         func() time.Time { return now },
		}

		for i := range 5 {
			rl.recordGlobal()
			if rl.global.currCount != i+1 {
				t.Errorf("after %d records: expected currCount=%d, got %d", i+1, i+1, rl.global.currCount)
			}
		}
	})
}

// ---- rateLimitState per-domain ----

func TestRateLimitStateDomain(t *testing.T) {
	t.Run("allows unknown domain", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		rl := &rateLimitState{
			perDomainLimit: &RateLimit{Limit: 1, Duration: caddy.Duration(time.Minute)},
			domains:        make(map[string]*windowCounter),
			now:            func() time.Time { return now },
		}

		if err := rl.checkDomain("example.com"); err != nil {
			t.Fatalf("expected allow for unknown domain, got %v", err)
		}
	})

	t.Run("allows requests below the per-domain limit", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		rl := &rateLimitState{
			perDomainLimit: &RateLimit{Limit: 3, Duration: caddy.Duration(time.Minute)},
			domains:        make(map[string]*windowCounter),
			now:            func() time.Time { return now },
		}

		rl.recordDomain("example.com")
		rl.recordDomain("example.com")

		if err := rl.checkDomain("example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("denies at the per-domain limit", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		rl := &rateLimitState{
			perDomainLimit: &RateLimit{Limit: 2, Duration: caddy.Duration(time.Minute)},
			domains:        make(map[string]*windowCounter),
			now:            func() time.Time { return now },
		}

		rl.recordDomain("example.com")
		rl.recordDomain("example.com")

		err := rl.checkDomain("example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("counters are independent per domain", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		rl := &rateLimitState{
			perDomainLimit: &RateLimit{Limit: 1, Duration: caddy.Duration(time.Minute)},
			domains:        make(map[string]*windowCounter),
			now:            func() time.Time { return now },
		}

		rl.recordDomain("example.com")

		err := rl.checkDomain("example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected example.com to be denied, got %v", err)
		}

		if err := rl.checkDomain("example.net"); err != nil {
			t.Fatalf("expected example.net to be unaffected, got %v", err)
		}
	})

	t.Run("evicts stale zero-estimate entry lazily", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		current := now
		rl := &rateLimitState{
			perDomainLimit: &RateLimit{Limit: 1, Duration: caddy.Duration(time.Minute)},
			domains:        make(map[string]*windowCounter),
			now:            func() time.Time { return current },
		}

		rl.recordDomain("example.com")

		if _, ok := rl.domains["example.com"]; !ok {
			t.Fatal("expected entry to exist after record")
		}

		// Advance past two windows so both buckets clear and estimate drops to zero.
		current = now.Add(2 * time.Minute)

		if err := rl.checkDomain("example.com"); err != nil {
			t.Fatalf("expected allow after expiry, got %v", err)
		}

		if _, ok := rl.domains["example.com"]; ok {
			t.Error("expected stale entry to be evicted")
		}
	})

	t.Run("recordDomain creates entry for unseen domain", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		rl := &rateLimitState{
			perDomainLimit: &RateLimit{Limit: 5, Duration: caddy.Duration(time.Minute)},
			domains:        make(map[string]*windowCounter),
			now:            func() time.Time { return now },
		}

		rl.recordDomain("example.com")

		w, ok := rl.domains["example.com"]
		if !ok {
			t.Fatal("expected entry to be created")
		}
		if w.currCount != 1 {
			t.Errorf("expected currCount=1, got %d", w.currCount)
		}
	})

	t.Run("recordDomain increments existing entry", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		rl := &rateLimitState{
			perDomainLimit: &RateLimit{Limit: 10, Duration: caddy.Duration(time.Minute)},
			domains:        make(map[string]*windowCounter),
			now:            func() time.Time { return now },
		}

		for i := range 4 {
			rl.recordDomain("example.com")
			if rl.domains["example.com"].currCount != i+1 {
				t.Errorf("after %d records: expected currCount=%d, got %d", i+1, i+1, rl.domains["example.com"].currCount)
			}
		}
	})

	t.Run("allows again after two full windows have elapsed", func(t *testing.T) {
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		current := now
		rl := &rateLimitState{
			perDomainLimit: &RateLimit{Limit: 1, Duration: caddy.Duration(time.Minute)},
			domains:        make(map[string]*windowCounter),
			now:            func() time.Time { return current },
		}

		rl.recordDomain("example.com")

		if err := rl.checkDomain("example.com"); !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected denial before reset, got %v", err)
		}

		current = now.Add(2 * time.Minute)

		if err := rl.checkDomain("example.com"); err != nil {
			t.Fatalf("expected allow after window reset, got %v", err)
		}
	})
}
