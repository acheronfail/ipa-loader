package apple

import (
	"context"
	"strings"
	"testing"
)

func TestAuthenticationRequiresCompleteIdentity(t *testing.T) {
	values, _ := testHeaders(context.Background())
	out, err := validateHeaders(values)
	if err != nil || len(out) != len(requiredHeaders) {
		t.Fatal("complete identity rejected", err)
	}
	out[requiredHeaders[0]] = "changed"
	if values[requiredHeaders[0]] == "changed" {
		t.Fatal("provider-owned headers were mutated")
	}
	for _, name := range requiredHeaders {
		t.Run(name, func(t *testing.T) {
			for _, value := range []string{"", "private\r\ninjected", "private\tvalue", "private\x7f", strings.Repeat("x", 65537)} {
				bad := cloneHeaders(values)
				bad[name] = value
				if _, err := validateHeaders(bad); err == nil || strings.Contains(err.Error(), "private") {
					t.Fatal("invalid identity accepted or disclosed")
				}
			}
			bad := cloneHeaders(values)
			delete(bad, name)
			if _, err := validateHeaders(bad); err == nil {
				t.Fatal("incomplete identity accepted")
			}
		})
	}
}
