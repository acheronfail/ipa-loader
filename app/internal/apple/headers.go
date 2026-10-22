package apple

import "strings"

func validateHeaders(values map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(requiredHeaders))
	for _, name := range requiredHeaders {
		value := values[name]
		if value == "" || len(value) > 65536 || strings.IndexFunc(value, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return nil, failure("Local authentication headers are incomplete")
		}
		out[name] = value
	}
	return out, nil
}
