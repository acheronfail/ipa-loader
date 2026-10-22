# ADI arithmetic

Pure-Go provisioning and MID/OTP computation using the Android-format profile
on all platforms. The caller handles HTTP exchanges and securely stores the
resulting machine state.

Use `NewAndroidProvisioning`, `FinishAndroidProvisioning` and
`AndroidMachineState.OTP`. See [anisette findings](../../../../research/anisette.md)
for the protocol and state format.

```sh
go -C app test ./internal/anisette/adimath
```
