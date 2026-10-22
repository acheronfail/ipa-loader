# Device transport

Go usbmuxd, lockdown/TLS, AFC and installation protocols.

| Host | Service |
| --- | --- |
| macOS | Built-in `/var/run/usbmuxd`; pair through Finder |
| Linux | System usbmuxd; configure USB permissions and pairing |
| Windows | Apple Mobile Device Service at `127.0.0.1:27015` |

Connect an unlocked, trusted iPhone. Enable Finder's Wi-Fi option for network
routes. `IPA_LOADER_USBMUXD_SOCKET` overrides the Unix socket path.

Uploads count acknowledged bytes. Cancellation stops observation but cannot
roll back a submitted installation. Callbacks must not re-enter the client.

See [transport findings](../../../research/device-transport.md) for recovery
and protocol details.
