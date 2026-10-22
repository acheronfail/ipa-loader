# Device transport and refresh findings

Device discovery, pairing and installation are separate layers. usbmuxd exposes
observed USB/network routes; a route is not proof that the phone is unlocked or
that a new pairing relationship may be created. Lockdown establishes paired
sessions and starts services, with TLS where required. Keep pairing material
private and let users establish trust through their platform's device tools.

The application uses shared Go protocol code over system usbmuxd on macOS and
Linux and installed Apple mobile-device support on Windows. The transport source
and wire boundaries are documented in
[the device package](../app/internal/mobiledevice/README.md).

AFC staging must count acknowledged writes, rather than bytes merely submitted
to a socket. A failed/unacknowledged write contributes zero confirmed progress.
Independent remote size/digest checks and a task-owned staging path allow retries
to distinguish incomplete transfer from uncertain installation submission.
Installation status callbacks and a local command's exit are not equivalent to
independent installed-app/version confirmation.

Cancellation closes observation and blocked transport work; it cannot undo an
installation already submitted to the phone. Recovery therefore needs a durable
record of submission/confirmation state. Cleanup must only remove task-owned
artifacts and must preserve enough information to resolve an uncertain outcome.
A paired network tunnel may be established on demand; disconnected tunnel state
alone does not establish that a device is offline.

The maintained iOS app first tries profile-only renewal when it can verify the
installed graph, original signer, matching portal records and new profile
authorization. It confirms installed profiles by independent readback and checks
that app inventory is unchanged. Uncertain submissions remain errors. Proven
incompatibility or an explicit device rejection can use full signing with a
retained/original IPA. Automatic refresh scheduling remains separate from these
manual refresh operations. See [the iOS guide](../app/IOS.md).

Synthetic transport and fixture tests exercise framing, acknowledgement,
cancellation, signing and recovery paths. Device checks require explicit opt-in
and a selected device.
