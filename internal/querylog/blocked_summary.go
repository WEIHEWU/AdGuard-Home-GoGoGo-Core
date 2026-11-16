package querylog

import (
	"container/list"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

const (
	// blockedSummaryMaxEntries caps the number of distinct aggregated blocked
	// diagnostic entries kept in memory.
	blockedSummaryMaxEntries = 256

	// blockedSummaryTTL bounds how long inactive aggregated blocked entries
	// stay in the in-memory summary without any background timer or disk I/O.
	blockedSummaryTTL = 5 * time.Minute
)

type blockedSummaryRecord struct {
	key       string
	qHost     string
	qType     string
	qClass    string
	clientID  string
	proto     ClientProto
	dst       string
	ip        net.IP
	result    filtering.Result
	firstSeen time.Time
	lastSeen  time.Time
	count     int
}

// blockedSummary maintains a bounded, memory-only aggregation of recent
// actually-blocked events so infrequent blocks (such as a single SNI reset)
// remain visible even after high-frequency retries overwrite the raw ring.
type blockedSummary struct {
	mu         sync.Mutex
	order      *list.List
	byKey      map[string]*list.Element
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
}

func newBlockedSummary(ttl time.Duration, maxEntries int) *blockedSummary {
	if ttl <= 0 {
		ttl = blockedSummaryTTL
	}
	if maxEntries <= 0 {
		maxEntries = blockedSummaryMaxEntries
	}

	return &blockedSummary{
		order:      list.New(),
		byKey:      make(map[string]*list.Element),
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

func isBlockedSummaryReason(r filtering.Reason) bool {
	switch r {
	case filtering.FilteredBlockList,
		filtering.FilteredSNI,
		filtering.FilteredSafeBrowsing,
		filtering.FilteredParental,
		filtering.FilteredInvalid:
		return true
	default:
		return false
	}
}

func isBlockedSummaryEntry(e *logEntry) bool {
	if e == nil || e.PredictedBlocked || !e.Result.IsFiltered {
		return false
	}

	return isBlockedSummaryReason(e.Result.Reason)
}

func buildBlockedSummaryKey(e *logEntry) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(e.QHost))
	b.WriteByte(0)
	b.WriteString(e.Result.Reason.String())
	b.WriteByte(0)
	for i, r := range e.Result.Rules {
		if i > 0 {
			b.WriteByte('|')
		}
		b.WriteString(strconv.FormatInt(int64(r.FilterListID), 10))
		b.WriteByte(':')
		b.WriteString(r.Text)
	}
	b.WriteByte(0)
	b.WriteString(e.ClientID)
	b.WriteByte('|')
	if len(e.IP) > 0 {
		b.WriteString(e.IP.String())
	}

	return b.String()
}

func cloneRules(rules []*filtering.ResultRule) []*filtering.ResultRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]*filtering.ResultRule, len(rules))
	for i, r := range rules {
		if r == nil {
			continue
		}
		cp := *r
		out[i] = &cp
	}

	return out
}

func (s *blockedSummary) purgeExpiredLocked(now time.Time) {
	for front := s.order.Front(); front != nil; {
		rec := front.Value.(*blockedSummaryRecord)
		if now.Sub(rec.lastSeen) <= s.ttl {
			break
		}
		next := front.Next()
		delete(s.byKey, rec.key)
		s.order.Remove(front)
		front = next
	}
}

func (s *blockedSummary) record(entry *logEntry) {
	if !isBlockedSummaryEntry(entry) {
		return
	}

	ts := entry.Time
	if ts.IsZero() {
		ts = s.now()
	}
	key := buildBlockedSummaryKey(entry)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.purgeExpiredLocked(s.now())

	if elem, ok := s.byKey[key]; ok {
		rec := elem.Value.(*blockedSummaryRecord)
		rec.count++
		if ts.After(rec.lastSeen) {
			rec.lastSeen = ts
		}
		if entry.Dst != "" {
			rec.dst = entry.Dst
		}
		rec.qType = entry.QType
		s.order.MoveToBack(elem)

		return
	}

	rec := &blockedSummaryRecord{
		key:       key,
		qHost:     entry.QHost,
		qType:     entry.QType,
		qClass:    entry.QClass,
		clientID:  entry.ClientID,
		proto:     entry.ClientProto,
		dst:       entry.Dst,
		ip:        slices.Clone(entry.IP),
		result: filtering.Result{
			Rules:      cloneRules(entry.Result.Rules),
			Reason:     entry.Result.Reason,
			IsFiltered: entry.Result.IsFiltered,
		},
		firstSeen: ts,
		lastSeen:  ts,
		count:     1,
	}
	elem := s.order.PushBack(rec)
	s.byKey[key] = elem

	for s.order.Len() > s.maxEntries {
		oldest := s.order.Front()
		if oldest == nil {
			break
		}
		oldRec := oldest.Value.(*blockedSummaryRecord)
		delete(s.byKey, oldRec.key)
		s.order.Remove(oldest)
	}
}

func (s *blockedSummary) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.order.Init()
	clear(s.byKey)
}

func (s *blockedSummary) snapshotNewestFirst() []*blockedSummaryRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.purgeExpiredLocked(s.now())

	res := make([]*blockedSummaryRecord, 0, s.order.Len())
	for e := s.order.Back(); e != nil; e = e.Prev() {
		src := e.Value.(*blockedSummaryRecord)
		cp := *src
		cp.ip = slices.Clone(src.ip)
		cp.result.Rules = cloneRules(src.result.Rules)
		res = append(res, &cp)
	}

	return res
}

func (l *queryLog) handleBlockedSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	limit := blockedSummaryMaxEntries
	if rawLimit := q.Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			aghhttp.ErrorAndLog(
				ctx,
				l.logger,
				r,
				w,
				http.StatusBadRequest,
				"invalid limit parameter: %q",
				rawLimit,
			)
			return
		}
		if parsed < limit {
			limit = parsed
		}
	}

	searchTerm := strings.ToLower(strings.TrimSpace(q.Get("search")))
	var searchASCII string
	if searchTerm != "" {
		if a, err := idna.ToASCII(searchTerm); err == nil && a != searchTerm {
			searchASCII = a
		}
	}

	var enabled bool
	var records []*blockedSummaryRecord
	func() {
		l.confMu.RLock()
		defer l.confMu.RUnlock()

		enabled = l.conf.Enabled
		if !enabled || l.blockedSummary == nil {
			return
		}
		raw := l.blockedSummary.snapshotNewestFirst()
		cache := clientCache{}
		for _, rec := range raw {
			if l.isIgnored(rec.qHost) {
				continue
			}
			var ids []string
			if rec.clientID != "" {
				ids = append(ids, rec.clientID)
			}
			if len(rec.ip) > 0 {
				ids = append(ids, rec.ip.String())
			}
			cli, err := l.client(rec.clientID, rec.ip.String(), cache)
			if err != nil {
				l.logger.DebugContext(ctx, "finding client for blocked summary", slogutil.KeyError, err)
			}
			if cli != nil && cli.IgnoreQueryLog {
				continue
			}
			records = append(records, rec)
		}
	}()

	var anonFunc aghnet.IPMutFunc = func(net.IP) {}
	if l.anonymizer != nil {
		if fn := l.anonymizer.Load(); fn != nil {
			anonFunc = fn
		}
	}

	cache := clientCache{}
	data := make([]jobject, 0, min(limit, len(records)))
	for _, rec := range records {
		if !enabled {
			break
		}
		if searchTerm != "" && !matchesSummarySearch(rec, searchTerm, searchASCII) {
			continue
		}

		entIP := slices.Clone(rec.ip)
		anonFunc(entIP)

		qPayload := jobject{
			"type":  rec.qType,
			"class": rec.qClass,
			"name":  rec.qHost,
		}
		if uName, err := idna.ToUnicode(rec.qHost); err == nil && uName != "" && uName != rec.qHost {
			qPayload["unicode_name"] = uName
		}

		item := jobject{
			"domain":       rec.qHost,
			"question":     qPayload,
			"reason":       rec.result.Reason.String(),
			"is_sni":       rec.result.Reason == filtering.FilteredSNI,
			"count":        rec.count,
			"first_time":   rec.firstSeen.Format(time.RFC3339Nano),
			"time":         rec.lastSeen.Format(time.RFC3339Nano),
			"client":       entIP,
			"client_proto": rec.proto,
			"destination":  rec.dst,
			"rules":        resultRulesToJSONRules(rec.result.Rules),
		}

		if entIP.Equal(rec.ip) {
			if cli, err := l.client(rec.clientID, rec.ip.String(), cache); err == nil && cli != nil {
				item["client_info"] = cli
			}
		}
		if rec.clientID != "" {
			item["client_id"] = rec.clientID
		}
		if len(rec.result.Rules) > 0 {
			first := rec.result.Rules[0]
			if first != nil && first.Text != "" {
				item["rule"] = first.Text
				item["filterId"] = first.FilterListID
			}
		}

		data = append(data, item)
		if len(data) >= limit {
			break
		}
	}

	resp := jobject{
		"max_entries":    blockedSummaryMaxEntries,
		"ttl_seconds":    int(blockedSummaryTTL.Seconds()),
		"retention_note": fmt.Sprintf("memory_only_max_%d_ttl_%ds", blockedSummaryMaxEntries, int(blockedSummaryTTL.Seconds())),
		"total":          len(data),
		"data":           data,
	}

	aghhttp.WriteJSONResponseOK(ctx, l.logger, w, r, resp)
}

func matchesSummarySearch(rec *blockedSummaryRecord, searchLower, searchASCII string) bool {
	h := strings.ToLower(rec.qHost)
	if strings.Contains(h, searchLower) || (searchASCII != "" && strings.Contains(h, searchASCII)) {
		return true
	}
	if uName, err := idna.ToUnicode(rec.qHost); err == nil && uName != "" {
		if strings.Contains(strings.ToLower(uName), searchLower) {
			return true
		}
	}
	for _, r := range rec.result.Rules {
		if r != nil && strings.Contains(strings.ToLower(r.Text), searchLower) {
			return true
		}
	}
	_ = dns.TypeA
	return false
}
