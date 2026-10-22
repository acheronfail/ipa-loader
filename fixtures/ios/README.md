# Fixture sources

Small iOS apps testing updates, frameworks/dylibs, extensions and shared storage.
Build from the repository root with Xcode's iPhoneOS SDK and Python 3:

```sh
sh scripts/build_fixture.sh
python3 scripts/build_framework_fixture.py 1
python3 scripts/build_framework_fixture.py 3 --universal
python3 scripts/build_extension_fixture.py 1
python3 scripts/build_extension_fixture.py 1 --free-account
python3 scripts/build_sharing_fixture.py 12
```

Outputs go to `fixtures/build/`. Reviewed inputs and rebuild commands are in
[the catalog](../ipas/manifest.json). The baseline pair preserves a saved counter
across updates. Sharing fixtures use synthetic group identifiers.

`prepare_windows_fixtures.py` creates inputs for the Windows device-check harnesses.
