//go:build !android_slim

package querylog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// reasonCodes is a set of all valid reason codes.
var reasonCodes = [...]string{
	filtering.NotFilteredAllowList: "1",
	filtering.NotFilteredError:     "2",
	filtering.FilteredBlockList:    "3",
	filtering.FilteredSafeBrowsing: "4",
	filtering.FilteredParental:     "5",
	filtering.FilteredInvalid:      "6",
	filtering.Rewritten:            "9",
	filtering.RewrittenAutoHosts:   "10",
	filtering.RewrittenRule:        "11",
	filtering.FilteredSNI:          "12",
	filtering.NotFilteredSNI:       "13",
}

// quickMatchClientFunc is a simplified client finder for quick matches.
type quickMatchClientFunc = func(
	ctx context.Context,
	logger *slog.Logger,
	clientID, ip string,
) (c *Client)

// quickMatch quickly checks if the line matches the given search parameters.
func (s *searchParams) quickMatch(
	ctx context.Context,
	logger *slog.Logger,
	line string,
	findClient quickMatchClientFunc,
) (ok bool) {
	for _, c := range s.searchCriteria {
		if !c.quickMatch(ctx, logger, line, findClient) {
			return false
		}
	}

	return true
}

// quickMatch quickly checks if the line matches the given search criterion.
func (c *searchCriterion) quickMatch(
	ctx context.Context,
	logger *slog.Logger,
	line string,
	findClient quickMatchClientFunc,
) (ok bool) {
	switch c.criterionType {
	case ctTerm:
		host := readJSONValue(line, `"QH":"`)
		ip := readJSONValue(line, `"IP":"`)
		clientID := readJSONValue(line, `"CID":"`)

		var name string
		if cli := findClient(ctx, logger, clientID, ip); cli != nil {
			name = cli.Name
		}

		if c.strict {
			return ctDomainOrClientCaseStrict(c.value, c.asciiVal, clientID, name, host, ip)
		}

		return ctDomainOrClientCaseNonStrict(c.value, c.asciiVal, clientID, name, host, ip)
	case ctFilteringStatus:
		return true
	case ctReason:
		reasonCode := readJSONNumericValue(line, `"Reason":`)
		if reasonCode == "" {
			return slices.Contains(c.values, filtering.NotFilteredNotFound.String())
		}

		idx := slices.Index(reasonCodes[:], reasonCode)
		if idx == -1 {
			return false
		}

		return slices.Contains(c.values, filtering.Reason(idx).String())
	default:
		return true
	}
}

func (r *qLogReader) seekRecord(ctx context.Context, olderThan time.Time) (err error) {
	if olderThan.IsZero() {
		return r.SeekStart()
	}

	err = r.seekTS(ctx, olderThan.UnixNano())
	if err == nil {
		_, err = r.ReadNext()
	}

	return err
}

func (l *queryLog) setQLogReader(
	ctx context.Context,
	olderThan time.Time,
) (qr *qLogReader, err error) {
	files := []string{
		l.logFile + ".1",
		l.logFile,
	}

	r, err := newQLogReader(ctx, l.logger, files)
	if err != nil {
		return nil, fmt.Errorf("opening qlog reader: %w", err)
	}

	err = r.seekRecord(ctx, olderThan)
	if err != nil {
		defer func() { err = errors.WithDeferred(err, r.Close()) }()
		l.logger.DebugContext(ctx, "cannot seek", "older_than", olderThan, slogutil.KeyError, err)

		return nil, nil
	}

	return r, nil
}

func (l *queryLog) readEntries(
	ctx context.Context,
	r *qLogReader,
	params *searchParams,
	cache clientCache,
	totalLimit int,
) (entries []*logEntry, oldestNano int64, total int) {
	for total < params.maxFileScanEntries || params.maxFileScanEntries <= 0 {
		ent, ts, rErr := l.readNextEntry(ctx, r, params, cache)
		if rErr == io.EOF {
			oldestNano = 0

			break
		} else if rErr != nil {
			l.logger.ErrorContext(ctx, "reading next entry", slogutil.KeyError, rErr)
		}

		oldestNano = ts
		total++

		if ent == nil {
			continue
		}

		entries = append(entries, ent)
		if len(entries) == totalLimit {
			break
		}
	}

	return entries, oldestNano, total
}

func (l *queryLog) searchFiles(
	ctx context.Context,
	params *searchParams,
	cache clientCache,
) (entries []*logEntry, oldest time.Time, total int) {
	r, err := l.setQLogReader(ctx, params.olderThan)
	if err != nil {
		l.logger.ErrorContext(ctx, "searching files", slogutil.KeyError, err)
	}

	if r == nil {
		return entries, oldest, 0
	}

	defer func() {
		if closeErr := r.Close(); closeErr != nil {
			l.logger.ErrorContext(ctx, "closing files", slogutil.KeyError, closeErr)
		}
	}()

	totalLimit := params.offset + params.limit
	entries, oldestNano, total := l.readEntries(ctx, r, params, cache, totalLimit)
	if oldestNano != 0 {
		oldest = time.Unix(0, oldestNano)
	}

	return entries, oldest, total
}

type quickMatchClientFinder struct {
	client func(clientID, ip string, cache clientCache) (c *Client, err error)
	cache  clientCache
}

func (f quickMatchClientFinder) findClient(
	ctx context.Context,
	logger *slog.Logger,
	clientID string,
	ip string,
) (c *Client) {
	var err error
	c, err = f.client(clientID, ip, f.cache)
	if err != nil {
		logger.ErrorContext(
			ctx,
			"enriching file record for quick search",
			"client_ip", ip,
			"client_id", clientID,
			slogutil.KeyError, err,
		)
	}

	return c
}

func (l *queryLog) readNextEntry(
	ctx context.Context,
	r *qLogReader,
	params *searchParams,
	cache clientCache,
) (e *logEntry, ts int64, err error) {
	var line string
	line, err = r.ReadNext()
	if err != nil {
		return nil, 0, err
	}

	clientFinder := quickMatchClientFinder{
		client: l.client,
		cache:  cache,
	}

	if !params.quickMatch(ctx, l.logger, line, clientFinder.findClient) {
		ts = readQLogTimestamp(ctx, l.logger, line)

		return nil, ts, nil
	}

	e = &logEntry{}
	l.decodeLogEntry(ctx, e, line)

	if l.isIgnored(e.QHost) {
		return nil, ts, nil
	}

	e.client, err = l.client(e.ClientID, e.IP.String(), cache)
	if err != nil {
		l.logger.ErrorContext(
			ctx,
			"enriching file record",
			"at", e.Time,
			"client_ip", e.IP,
			"client_id", e.ClientID,
			slogutil.KeyError, err,
		)
	}

	if e.client != nil && e.client.IgnoreQueryLog {
		return nil, ts, nil
	}

	ts = e.Time.UnixNano()
	if !params.match(e) {
		return nil, ts, nil
	}

	return e, ts, nil
}
