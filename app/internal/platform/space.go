package platform

import "fmt"

func checkExtractionSpace(work string, expanded uint64) error {
	available, err := availableDiskBytes(work)
	if err != nil {
		return failure("Could not check free disk space for unpacking the IPA")
	}
	return requireExtractionSpace(expanded, available)
}

func requireExtractionSpace(expanded, available uint64) error {
	if expanded > available {
		return fmt.Errorf("Not enough free disk space to unpack this IPA (needs %.1f GiB; %.1f GiB available)", float64(expanded)/(1<<30), float64(available)/(1<<30))
	}
	return nil
}
