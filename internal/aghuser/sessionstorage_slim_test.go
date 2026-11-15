//go:build android_slim

package aghuser

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionStorageSlim_PrunesExpiredOnNewAndRespectsBoundary(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	clock := &faketime.Clock{
		OnNow: func() time.Time {
			return now
		},
	}

	const ttl = 10 * time.Minute
	ds, err := NewDefaultSessionStorage(ctx, &DefaultSessionStorageConfig{
		Clock:      clock,
		SessionTTL: ttl,
	})
	require.NoError(t, err)

	u1 := &User{ID: MustNewUserID(), Login: "alice"}
	u2 := &User{ID: MustNewUserID(), Login: "bob"}

	// Create session s1 at T=0 (expires at T=10m).
	s1, err := ds.New(ctx, u1)
	require.NoError(t, err)

	// Advance to T=5m and create session s2 (expires at T=15m).
	now = now.Add(5 * time.Minute)
	s2, err := ds.New(ctx, u2)
	require.NoError(t, err)

	// Advance to exact expiration boundary of s1 (T=10m).
	// Boundary check: now.After(s1.Expire) is false at exact equality, so s1 must remain valid.
	now = now.Add(5 * time.Minute)
	got1, err := ds.FindByToken(ctx, s1.Token)
	require.NoError(t, err)
	require.NotNil(t, got1)

	s3, err := ds.New(ctx, u1)
	require.NoError(t, err)
	assert.Len(t, ds.sessions, 3)

	// Advance 1ns past s1.Expire (T=10m + 1ns). Never call FindByToken(s1.Token);
	// instead call New() and verify that abandoned expired s1 is pruned while valid s2 & s3 remain.
	now = now.Add(time.Nanosecond)
	s4, err := ds.New(ctx, u2)
	require.NoError(t, err)

	ds.mu.Lock()
	_, hasS1 := ds.sessions[s1.Token]
	_, hasS2 := ds.sessions[s2.Token]
	_, hasS3 := ds.sessions[s3.Token]
	_, hasS4 := ds.sessions[s4.Token]
	ds.mu.Unlock()

	assert.False(t, hasS1, "expired unvisited session s1 should be pruned on New()")
	assert.True(t, hasS2, "valid session s2 must be retained")
	assert.True(t, hasS3, "valid session s3 must be retained")
	assert.True(t, hasS4, "newly created session s4 must be retained")
}

func TestSessionStorageSlim_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	clock := &faketime.Clock{
		OnNow: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			now = now.Add(100 * time.Millisecond)
			return now
		},
	}

	ds, err := NewDefaultSessionStorage(ctx, &DefaultSessionStorageConfig{
		Clock:      clock,
		SessionTTL: 2 * time.Second,
	})
	require.NoError(t, err)

	u := &User{ID: MustNewUserID(), Login: "admin"}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				s, err := ds.New(ctx, u)
				require.NoError(t, err)
				_, err = ds.FindByToken(ctx, s.Token)
				require.NoError(t, err)
				err = ds.DeleteByToken(ctx, s.Token)
				require.NoError(t, err)
			}
		}()
	}
	wg.Wait()
}
