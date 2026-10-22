package apple

import (
	"testing"
	"time"
)

func TestQuotaClassification(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	membership := func() map[string]any {
		return map[string]any{"name": "Apple Developer Program", "status": "active", "dateStart": now.Add(-24 * time.Hour), "dateExpire": now.Add(24 * time.Hour)}
	}
	cases := []struct {
		name             string
		record           map[string]any
		unlimited, known bool
		limit            int
	}{
		{"free", map[string]any{"xcodeFreeOnly": true}, false, true, 10},
		{"missing", map[string]any{}, false, false, 0},
		{"false alone", map[string]any{"xcodeFreeOnly": false}, false, false, 0},
		{"organization alone", map[string]any{"type": "Company/Organization"}, false, false, 0},
		{"paid", map[string]any{"xcodeFreeOnly": false, "memberships": []any{membership()}}, true, true, 0},
	}
	for _, field := range []string{"name", "status", "dateStart", "dateExpire"} {
		m := membership()
		m[field] = "unknown"
		cases = append(cases, struct {
			name             string
			record           map[string]any
			unlimited, known bool
			limit            int
		}{"malformed " + field, map[string]any{"xcodeFreeOnly": false, "memberships": []any{m}}, false, false, 0})
	}
	for _, kind := range []string{"expired", "future", "missing dates", "RFC3339", "missing explicit flag", "unknown product"} {
		m := membership()
		record := map[string]any{"xcodeFreeOnly": false, "memberships": []any{m}}
		known := false
		switch kind {
		case "expired":
			m["dateExpire"] = now
		case "future":
			m["dateStart"] = now.Add(time.Hour)
		case "missing dates":
			delete(m, "dateStart")
		case "RFC3339":
			m["dateStart"] = now.Add(-time.Hour).Format(time.RFC3339)
			m["dateExpire"] = now.Add(time.Hour).Format(time.RFC3339)
			known = true
		case "missing explicit flag":
			delete(record, "xcodeFreeOnly")
		case "unknown product":
			m["name"] = "Unknown Membership"
		}
		cases = append(cases, struct {
			name             string
			record           map[string]any
			unlimited, known bool
			limit            int
		}{kind, record, known, known, 0})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, k, l := teamQuota(tc.record, now)
			if u != tc.unlimited || k != tc.known || l != tc.limit {
				t.Fatal("quota state differs from conservative contract")
			}
		})
	}
}
