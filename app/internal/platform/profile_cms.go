package platform

import (
	"ipa-loader/app/internal/cms"
)

func decodeProfile(path string) ([]byte, error) {
	b, err := readLimited(path, 16<<20)
	if err != nil {
		return nil, err
	}
	content, _, _, err := cms.Verify(b, nil, nil)
	return content, err
}
