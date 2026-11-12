package aghuser

import (
	"context"
	"log/slog"
	"time"

	"github.com/AdguardTeam/golibs/timeutil"
)

// SessionStorage is an interface that defines methods for handling web user
// sessions.  All methods must be safe for concurrent use.
type SessionStorage interface {
	// New creates a new session for the web user.
	New(ctx context.Context, u *User) (s *Session, err error)

	// FindByToken returns the stored session for the web user based on the
	// session token.
	FindByToken(ctx context.Context, t SessionToken) (s *Session, err error)

	// DeleteByToken removes a stored web user session by the provided token.
	DeleteByToken(ctx context.Context, t SessionToken) (err error)

	// Close releases the web user sessions database resources.
	Close() (err error)
}

// DefaultSessionStorageConfig represents the web user session storage
// configuration structure.
type DefaultSessionStorageConfig struct {
	// Logger is used for logging the operation of the session storage.  It must
	// not be nil.
	Logger *slog.Logger

	// Clock is used to get the current time.  It must not be nil.
	Clock timeutil.Clock

	// UserDB contains the web user information such as ID, login, and password.
	// It must not be nil.
	UserDB DB

	// DBPath is the path to the database file where session data is stored.
	DBPath string

	// SessionTTL is the default Time-To-Live duration for web user sessions.
	SessionTTL time.Duration
}
