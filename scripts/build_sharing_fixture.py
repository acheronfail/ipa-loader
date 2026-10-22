#!/usr/bin/env python3
"""Build an owned ad-hoc input IPA with literal original sharing group names."""
import hashlib
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
version = sys.argv[1] if len(sys.argv) == 2 else "1"
if not version.isdecimal() or not 1 <= int(version) <= 999:
    raise SystemExit("Use a fixture build number between 1 and 999")
output = ROOT / "fixtures/build" / f"sharing-v{version}"
if output.exists(): shutil.rmtree(output)
app = output / "Payload/SharingTest.app"
extension = app / "PlugIns/SharingShare.appex"
extension.mkdir(parents=True)
sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
common = ["xcrun", "--sdk", "iphoneos", "clang", "-target", "arm64-apple-ios15.0", "-isysroot", sdk,
    "-fobjc-arc", "-O2", "-Wall", "-Wextra", "-Wno-unused-parameter", "-framework", "UIKit", "-framework", "Foundation",
    "-framework", "Security", "-Wl,-headerpad,0x1000", f'-DFIXTURE_VERSION="{version}"']
source = ROOT / "fixtures/ios/sharing-fixture.m"
subprocess.run(common+[str(source),"-o",str(app/"SharingTest")],check=True)
subprocess.run(common+["-DSHARING_EXTENSION","-fapplication-extension",str(source),"-Wl,-e,_NSExtensionMain","-o",str(extension/"SharingShare")],check=True)
base = dict(CFBundleInfoDictionaryVersion="6.0",CFBundleShortVersionString=f"{version}.0",CFBundleVersion=version,MinimumOSVersion="15.0",CFBundleSupportedPlatforms=["iPhoneOS"],UIDeviceFamily=[1,2])
main = dict(base,CFBundleIdentifier="org.ipaloader.sharingtest",CFBundleExecutable="SharingTest",CFBundleName="SharingTest",CFBundleDisplayName="Sharing Test",CFBundlePackageType="APPL",LSRequiresIPhoneOS=True,UILaunchScreen={})
child = dict(base,CFBundleIdentifier=main["CFBundleIdentifier"]+".share",CFBundleExecutable="SharingShare",CFBundleName="SharingShare",CFBundleDisplayName="IPA Loader Sharing",CFBundlePackageType="XPC!",NSExtension=dict(NSExtensionPointIdentifier="com.apple.share-services",NSExtensionPrincipalClass="SharingController",NSExtensionAttributes=dict(NSExtensionActivationRule=dict(NSExtensionActivationSupportsText=True))))
for bundle,info in [(extension,child),(app,main)]:
    (bundle/"Info.plist").write_bytes(plistlib.dumps(info))
    ent = {"application-identifier":"OLDTEAM001."+info["CFBundleIdentifier"],"com.apple.developer.team-identifier":"OLDTEAM001","get-task-allow":True,"com.apple.security.application-groups":["group.org.ipaloader.sharingfixture"],"keychain-access-groups":["OLDTEAM001."+info["CFBundleIdentifier"],"OLDTEAM001.org.ipaloader.sharingfixture"]}
    ent_path = output / (info["CFBundleExecutable"]+"-entitlements.plist")
    ent_path.write_bytes(plistlib.dumps(ent))
    subprocess.run(["codesign","--force","--sign","-","--generate-entitlement-der","--entitlements",str(ent_path),str(bundle)],check=True)
ipa = ROOT / "fixtures/build" / f"ipa-loader-sharing-v{version}-adhoc.ipa"
with zipfile.ZipFile(ipa,"w",compression=zipfile.ZIP_DEFLATED) as z:
    for p in sorted(app.rglob("*")):
        if not p.is_file(): continue
        item=zipfile.ZipInfo(p.relative_to(output).as_posix(),(2020,1,1,0,0,0));item.create_system=3
        item.external_attr=(0o100755 if p.name in ("SharingTest","SharingShare") else 0o100644)<<16
        item.compress_type=zipfile.ZIP_DEFLATED;z.writestr(item,p.read_bytes())
print(f"{hashlib.sha256(ipa.read_bytes()).hexdigest()}  {ipa}")
