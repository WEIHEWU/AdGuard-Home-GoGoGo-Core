//go:build android_slim

package aghuser

import (
	"context"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/timeutil"
)

// DefaultSessionStorage is the pure in-memory implementation of [SessionStorage]
// for android_slim builds (eliminating bbolt and sessions.db flash I/O).
type DefaultSessionStorage struct {
	mu         *sync.Mutex
	clock      timeutil.Clock
	sessions   map[SessionToken]*Session
	sessionTTL time.Duration
}

// NewDefaultSessionStorage returns a new in-memory *DefaultSessionStorage.
func NewDefaultSessionStorage(
	_ context.Context,
	conf *DefaultSessionStorageConfig,
) (ds *DefaultSessionStorage, err error) {
	return &DefaultSessionStorage{
		mu:         &sync.Mutex{},
		clock:      conf.Clock,
		sessions:   map[SessionToken]*Session{},
		sessionTTL: conf.SessionTTL,
	}, nil
}

// type check
var _ SessionStorage = (*DefaultSessionStorage)(nil)

// New implements the [SessionStorage] interface for *DefaultSessionStorage.
func (ds *DefaultSessionStorage) New(_ context.Context, u *User) (s *Session, err error) {
	now := ds.clock.Now()
	s = &Session{
		Token:     NewSessionToken(),
		UserID:    u.ID,
		UserLogin: u.Login,
		Expire:    now.Add(ds.sessionTTL),
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	for t, existing := range ds.sessions {
		if now.After(existing.Expire) {
			delete(ds.sessions, t)
		}
	}

	ds.sessions[s.Token] = s

	return s, nil
}

// FindByToken implements the [SessionStorage] interface for *DefaultSessionStorage.
func (ds *DefaultSessionStorage) FindByToken(_ context.Context, t SessionToken) (s *Session, err error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	s, ok := ds.sessions[t]
	if !ok {
		return nil, nil
	}

	if ds.clock.Now().After(s.Expire) {
		delete(ds.sessions, t)
		return nil, nil
	}

	return s, nil
}

// DeleteByToken implements the [SessionStorage] interface for *DefaultSessionStorage.
func (ds *DefaultSessionStorage) DeleteByToken(_ context.Context, t SessionToken) (err error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	delete(ds.sessions, t)

	return nil
}

// Close implements the [SessionStorage] interface for *DefaultSessionStorage.
func (ds *DefaultSessionStorage) Close() (err error) {
	return nil
}
