//go:build darwin && !ios

package platform

import (
	"context"
	"ipa-loader/app/internal/apple"
)

func Devices(ctx context.Context) ([]Device, error) {
	records, err := hostDevices(ctx)
	if err != nil {
		return nil, err
	}
	devices := make([]Device, 0, len(records))
	for _, record := range records {
		transport := record.Transport
		if transport == "Network" {
			transport = "WiFi"
		}
		devices = append(devices, Device{ID: record.UDID, UDID: record.UDID, Name: record.Name, Model: record.Model, OSVersion: record.OSVersion, Transport: transport})
	}
	return devices, nil
}
func Sideload(ctx context.Context, client *apple.Client, session *apple.Session, team, ipa string, device Device, progress func(Progress)) (Result, error) {
	return sideload(ctx, client, session, team, ipa, device, progress, func(ctx context.Context, work string) *engine { return newDarwinEngine(ctx, work, team) })
}
