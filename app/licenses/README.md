# Release attribution

`LICENSE.zsign` preserves attribution for the public Apple certificate chain
retained from the pinned zsign reference, revision
`9299685bab7ef99827e06e5dfda93af747386590`.

`LICENSE.zig` records the build compiler's license. Release notice collection also
copies installed Go/module licenses and the relevant Zig runtime notices.
`app/cmd/licenses` consumes this directory during packaging.
