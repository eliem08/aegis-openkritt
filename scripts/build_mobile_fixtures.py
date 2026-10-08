"""Build deterministic positive and negative APK fixtures using apktool and jarsigner in MobSF container."""

import subprocess
from pathlib import Path

CONTAINER = "aegis-mobsf"
APKTOOL_JAR = "/home/mobsf/Mobile-Security-Framework-MobSF/mobsf/StaticAnalyzer/tools/apktool_3.0.3.jar"

def main():
    dest_dir = Path("tests/fixtures/mobile")
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    script_in_container = """
import os
import shutil
import subprocess

# 1. Setup working directories
os.makedirs("/tmp/mobile_build", exist_ok=True)
shutil.rmtree("/tmp/mobile_build/positive", ignore_errors=True)
shutil.rmtree("/tmp/mobile_build/negative", ignore_errors=True)

shutil.copytree("/tmp/clipdump_decoded", "/tmp/mobile_build/positive")
shutil.copytree("/tmp/clipdump_decoded", "/tmp/mobile_build/negative")

# 2. Positive manifest: contains insecure permissions, exported component, allowBackup, debuggable
pos_manifest = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="opensecurity.positive" platformBuildVersionCode="24" platformBuildVersionName="7.0">
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <application android:allowBackup="true" android:debuggable="true" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:supportsRtl="true" android:theme="@style/AppTheme">
        <service android:enabled="true" android:exported="true" android:name="opensecurity.clipdump.ClipDumper"/>
    </application>
</manifest>'''

with open("/tmp/mobile_build/positive/AndroidManifest.xml", "w") as f:
    f.write(pos_manifest)

# 3. Negative manifest: secure, no dangerous permissions, allowBackup=false, exported=false
neg_manifest = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="opensecurity.clean" platformBuildVersionCode="24" platformBuildVersionName="7.0">
    <application android:allowBackup="false" android:debuggable="false" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:supportsRtl="true" android:theme="@style/AppTheme">
        <service android:enabled="true" android:exported="false" android:name="opensecurity.clipdump.ClipDumper"/>
    </application>
</manifest>'''

with open("/tmp/mobile_build/negative/AndroidManifest.xml", "w") as f:
    f.write(neg_manifest)

# 4. Build APKs with apktool
apktool = "/home/mobsf/Mobile-Security-Framework-MobSF/mobsf/StaticAnalyzer/tools/apktool_3.0.3.jar"
print("Building positive APK...")
subprocess.run(["java", "-jar", apktool, "b", "/tmp/mobile_build/positive", "-o", "/tmp/mobile_build/positive_insecure_unsigned.apk"], check=True)

print("Building negative APK...")
subprocess.run(["java", "-jar", apktool, "b", "/tmp/mobile_build/negative", "-o", "/tmp/mobile_build/negative_clean_unsigned.apk"], check=True)

# 5. Generate debug keystore and sign both APKs
keystore = "/tmp/mobile_build/debug.keystore"
if not os.path.exists(keystore):
    subprocess.run([
        "keytool", "-genkeypair", "-v",
        "-keystore", keystore,
        "-alias", "androiddebugkey",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-storepass", "android",
        "-keypass", "android",
        "-dname", "CN=Android Debug,O=Android,C=US"
    ], check=True)

for name in ["positive_insecure", "negative_clean"]:
    unsigned = f"/tmp/mobile_build/{name}_unsigned.apk"
    signed = f"/tmp/mobile_build/{name}.apk"
    shutil.copyfile(unsigned, signed)
    subprocess.run([
        "jarsigner", "-verbose",
        "-keystore", keystore,
        "-storepass", "android",
        "-keypass", "android",
        signed, "androiddebugkey"
    ], check=True)
    print(f"Successfully generated and signed {signed}")
"""
    # Write to container and execute
    proc = subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "python3", "-c", script_in_container],
        capture_output=True,
        text=True
    )
    print("STDOUT:\n", proc.stdout)
    if proc.stderr:
        print("STDERR:\n", proc.stderr)
    proc.check_returncode()

    # Copy files back to host
    for name in ["positive_insecure.apk", "negative_clean.apk"]:
        host_target = dest_dir / name
        subprocess.run(["docker", "cp", f"{CONTAINER}:/tmp/mobile_build/{name}", str(host_target)], check=True)
        print(f"Copied {name} -> {host_target} ({host_target.stat().st_size} bytes)")

if __name__ == "__main__":
    main()
