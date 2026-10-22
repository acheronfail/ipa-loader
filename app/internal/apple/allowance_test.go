package apple

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestObservedAppIDAllowance(t *testing.T) {
	team := Team{}
	applyAppIDAllowance(&team, map[string]any{"maxQuantity": uint64(10), "availableQuantity": uint64(4), "totalRecords": uint64(6)})
	if !team.LimitKnown || !team.AvailabilityKnown || team.AppIDsUnlimited || team.AppIDLimit != 10 || team.AppIDsAvailable != 4 {
		t.Fatal("live response quota shape not recognized")
	}
	for _, bad := range []map[string]any{
		{}, {"maxQuantity": 0, "availableQuantity": 0}, {"maxQuantity": 10, "availableQuantity": 11},
		{"maxQuantity": 10, "availableQuantity": -1}, {"maxQuantity": "10", "availableQuantity": 4},
		{"maxQuantity": true, "availableQuantity": 4}, {"maxQuantity": 10, "availableQuantity": 4.5},
	} {
		original := Team{LimitKnown: true, AppIDsUnlimited: true}
		candidate := original
		applyAppIDAllowance(&candidate, bad)
		if candidate != original {
			t.Fatal("invalid quota changed membership evidence")
		}
	}
	applyAppIDAllowance(&team, map[string]any{"maxQuantity": 10, "availableQuantity": 0})
	if !team.AvailabilityKnown || team.AppIDsAvailable != 0 {
		t.Fatal("exhausted allowance treated as unknown")
	}
}

func TestAllowanceLookupIsOptionalButCancellationPropagates(t *testing.T) {
	for _, mode := range []string{"observed", "unavailable", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := New(testHeaders)
			calls := 0
			client.HTTPClient.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if strings.HasSuffix(r.URL.Path, "/listTeams.action") {
					return reply(encoded(map[string]any{"resultCode": 0, "teams": []any{map[string]any{"teamId": "SYNTHETIC", "name": "Fixture team"}}})), nil
				}
				if !strings.HasSuffix(r.URL.Path, "/listAppIds.action") {
					t.Fatal("quota lookup used a mutating operation")
				}
				if mode == "cancelled" {
					cancel()
					return nil, context.Canceled
				}
				response := map[string]any{"resultCode": 0, "maxQuantity": 10, "availableQuantity": 4}
				if mode == "unavailable" {
					response = map[string]any{"resultCode": 1100}
				}
				return reply(encoded(response)), nil
			})
			teams, err := client.TeamsWithAllowance(ctx, testSession())
			if mode == "cancelled" {
				if err != context.Canceled {
					t.Fatal("cancelled quota lookup did not stop")
				}
				return
			}
			if err != nil || len(teams) != 1 || calls != 2 {
				t.Fatal("optional quota lookup blocked successful team lookup")
			}
			if teams[0].AvailabilityKnown != (mode == "observed") {
				t.Fatal("allowance certainty differs from response")
			}
		})
	}
}

func TestQuotaExhaustionResponseExplainsNextStep(t *testing.T) {
	client := New(testHeaders)
	client.HTTPClient.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return reply(encoded(map[string]any{"resultCode": 9120})), nil
	})
	_, err := client.Request(context.Background(), testSession(), "listAppIds", nil, "SYNTHETIC")
	if err == nil || !strings.Contains(err.Error(), "App ID limit") || !strings.Contains(err.Error(), "expires") {
		t.Fatal("quota error has no actionable explanation")
	}
}
