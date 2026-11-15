package stats

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnit_Deserialize(t *testing.T) {
	testCases := []struct {
		db   *unitDB
		name string
		want unit
	}{{
		name: "empty",
		want: unit{
			domains:            map[string]uint64{},
			blockedDomains:     map[string]uint64{},
			clients:            map[string]uint64{},
			nResult:            []uint64{0, 0, 0, 0, 0, 0},
			id:                 0,
			nTotal:             0,
			timeSum:            0,
			upstreamsResponses: map[string]uint64{},
			upstreamsTimeSum:   map[string]uint64{},
		},
		db: &unitDB{
			NResult:            []uint64{0, 0, 0, 0, 0, 0},
			Domains:            []countPair{},
			BlockedDomains:     []countPair{},
			Clients:            []countPair{},
			NTotal:             0,
			TimeAvg:            0,
			UpstreamsResponses: []countPair{},
			UpstreamsTimeSum:   []countPair{},
		},
	}, {
		name: "basic",
		want: unit{
			domains: map[string]uint64{
				"example.com": 1,
			},
			blockedDomains: map[string]uint64{
				"example.net": 1,
			},
			clients: map[string]uint64{
				"127.0.0.1": 2,
			},
			nResult: []uint64{0, 1, 1, 0, 0, 0},
			id:      0,
			nTotal:  2,
			timeSum: 246912,
			upstreamsResponses: map[string]uint64{
				"1.2.3.4": 2,
			},
			upstreamsTimeSum: map[string]uint64{
				"1.2.3.4": 246912,
			},
		},
		db: &unitDB{
			NResult: []uint64{0, 1, 1, 0, 0, 0},
			Domains: []countPair{{
				"example.com", 1,
			}},
			BlockedDomains: []countPair{{
				"example.net", 1,
			}},
			Clients: []countPair{{
				"127.0.0.1", 2,
			}},
			NTotal:  2,
			TimeAvg: 123456,
			UpstreamsResponses: []countPair{{
				"1.2.3.4", 2,
			}},
			UpstreamsTimeSum: []countPair{{
				"1.2.3.4", 246912,
			}},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := unit{}
			got.deserialize(tc.db)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestTopUpstreamsPairs(t *testing.T) {
	testCases := []struct {
		db            *unitDB
		name          string
		wantResponses []topAddrs
		wantAvgTime   []topAddrsFloat
	}{{
		name: "empty",
		db: &unitDB{
			NResult:            []uint64{0, 0, 0, 0, 0, 0},
			Domains:            []countPair{},
			BlockedDomains:     []countPair{},
			Clients:            []countPair{},
			NTotal:             0,
			TimeAvg:            0,
			UpstreamsResponses: []countPair{},
			UpstreamsTimeSum:   []countPair{},
		},
		wantResponses: []topAddrs{},
		wantAvgTime:   []topAddrsFloat{},
	}, {
		name: "basic",
		db: &unitDB{
			NResult:        []uint64{0, 0, 0, 0, 0, 0},
			Domains:        []countPair{},
			BlockedDomains: []countPair{},
			Clients:        []countPair{},
			NTotal:         0,
			TimeAvg:        0,
			UpstreamsResponses: []countPair{{
				"1.2.3.4", 2,
			}},
			UpstreamsTimeSum: []countPair{{
				"1.2.3.4", 246912,
			}},
		},
		wantResponses: []topAddrs{{
			"1.2.3.4": 2,
		}},
		wantAvgTime: []topAddrsFloat{{
			"1.2.3.4": 0.123456,
		}},
	}, {
		name: "sorted",
		db: &unitDB{
			NResult:        []uint64{0, 0, 0, 0, 0, 0},
			Domains:        []countPair{},
			BlockedDomains: []countPair{},
			Clients:        []countPair{},
			NTotal:         0,
			TimeAvg:        0,
			UpstreamsResponses: []countPair{
				{"3.3.3.3", 8},
				{"2.2.2.2", 4},
				{"4.4.4.4", 16},
				{"1.1.1.1", 2},
			},
			UpstreamsTimeSum: []countPair{
				{"3.3.3.3", 800_000_000},
				{"2.2.2.2", 40_000_000},
				{"4.4.4.4", 16_000_000_000},
				{"1.1.1.1", 2_000_000},
			},
		},
		wantResponses: []topAddrs{
			{"4.4.4.4": 16},
			{"3.3.3.3": 8},
			{"2.2.2.2": 4},
			{"1.1.1.1": 2},
		},
		wantAvgTime: []topAddrsFloat{
			{"4.4.4.4": 1000},
			{"3.3.3.3": 100},
			{"2.2.2.2": 10},
			{"1.1.1.1": 1},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotResponses, gotAvgTime := topUpstreamsPairs([]*unitDB{tc.db})
			assert.Equal(t, tc.wantResponses, gotResponses)
			assert.Equal(t, tc.wantAvgTime, gotAvgTime)
		})
	}
}

func TestConvertMapToSlice(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		got := convertMapToSlice(map[string]uint64{}, 5)
		assert.Empty(t, got)
		assert.Equal(t, 0, cap(got))
	})

	t.Run("less_than_limit", func(t *testing.T) {
		m := map[string]uint64{
			"b.example": 10,
			"a.example": 30,
			"c.example": 20,
		}
		got := convertMapToSlice(m, 5)
		require.Len(t, got, 3)
		assert.Equal(t, 3, cap(got))
		assert.Equal(t, []countPair{
			{Name: "a.example", Count: 30},
			{Name: "c.example", Count: 20},
			{Name: "b.example", Count: 10},
		}, got)
	})

	t.Run("equal_to_limit", func(t *testing.T) {
		m := map[string]uint64{
			"b.example": 10,
			"a.example": 30,
			"c.example": 20,
		}
		got := convertMapToSlice(m, 3)
		require.Len(t, got, 3)
		assert.Equal(t, 3, cap(got))
		assert.Equal(t, []countPair{
			{Name: "a.example", Count: 30},
			{Name: "c.example", Count: 20},
			{Name: "b.example", Count: 10},
		}, got)
	})

	t.Run("greater_than_limit_truncates_and_shrinks_backing_array", func(t *testing.T) {
		m := make(map[string]uint64, 1000)
		for i := range 1000 {
			m[fmt.Sprintf("domain-%04d.example.com", i)] = uint64(i + 1)
		}

		const limit = 10
		got := convertMapToSlice(m, limit)
		require.Len(t, got, limit)
		// Verify that a fresh backing array of exact capacity was allocated so the
		// full 1000-element array and its string pointers are not retained.
		assert.Equal(t, limit, cap(got))

		for i := range limit {
			wantCount := uint64(1000 - i)
			assert.Equal(t, wantCount, got[i].Count)
			assert.Equal(t, fmt.Sprintf("domain-%04d.example.com", 999-i), got[i].Name)
		}
	})

	t.Run("ties_preserve_counts_without_extra_tiebreak_rule", func(t *testing.T) {
		m := map[string]uint64{
			"tie1.example": 50,
			"tie2.example": 50,
			"low.example":  10,
			"high.example": 100,
		}
		got := convertMapToSlice(m, 3)
		require.Len(t, got, 3)
		assert.Equal(t, 3, cap(got))
		assert.Equal(t, countPair{Name: "high.example", Count: 100}, got[0])
		assert.Equal(t, uint64(50), got[1].Count)
		assert.Equal(t, uint64(50), got[2].Count)
		assert.NotEqual(t, got[1].Name, got[2].Name)
	})

	t.Run("no_extra_copy_when_not_truncated", func(t *testing.T) {
		m := map[string]uint64{
			"one.example": 1,
			"two.example": 2,
		}
		got := convertMapToSlice(m, 10)
		require.Len(t, got, 2)
		assert.Equal(t, 2, cap(got))
		assert.NotNil(t, unsafe.SliceData(got))
	})
}
