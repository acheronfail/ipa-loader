//go:build windows

package apple

import (
	"context"
	"strings"
	"testing"
)

func TestWindowsVerificationRefreshKeepsIdentityAndChallenge(t *testing.T) {
	original, _ := testHeaders(context.Background())
	c := New(func(context.Context) (map[string]string, error) {
		fresh := cloneHeaders(original)
		fresh["X-Apple-I-MD"] = "fresh-otp"
		return fresh, nil
	})
	headers := cloneHeaders(original)
	headers["security-code"] = "123456"
	headers["Content-Type"] = "application/json"
	if err := c.refreshVerificationHeaders(context.Background(), original, headers); err != nil {
		t.Fatal(err)
	}
	if headers["X-Apple-I-MD"] != "fresh-otp" || headers["security-code"] != "123456" || headers["Content-Type"] != "application/json" {
		t.Fatal("OTP refresh lost verification context")
	}
	if _, exists := headers["X-Apple-I-SRL-NO"]; exists {
		t.Fatal("serial leaked into verification request")
	}
	for _, field := range []string{"X-Apple-I-MD-M", "X-Mme-Device-Id", "X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-MMe-Client-Info", "X-Apple-I-SRL-NO", "X-Apple-Locale", "X-Apple-I-TimeZone"} {
		t.Run(field, func(t *testing.T) {
			c.provider = func(context.Context) (map[string]string, error) {
				fresh := cloneHeaders(original)
				fresh[field] = "private-drift"
				return fresh, nil
			}
			err := c.refreshVerificationHeaders(context.Background(), original, headers)
			if err == nil || strings.Contains(err.Error(), "private-drift") {
				t.Fatal("identity drift accepted or disclosed")
			}
		})
	}
}
