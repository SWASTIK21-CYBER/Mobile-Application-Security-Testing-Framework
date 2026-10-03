# MASTF – Mobile Application Security Testing Framework

## 1. What this project is
A repeatable workflow (plus a small Python tool) that tests Android apps for the
OWASP Mobile Top 10 by combining four stages:

| Stage | Tool | What it finds | OWASP |
|---|---|---|---|
| Static analysis | MobSF | Manifest flaws, hardcoded secrets, weak crypto, exported components | M1, M3, M7, M8, M10 |
| Dynamic analysis | Frida | Runtime data leaks, insecure storage writes, logic/auth bypass | M3, M9 |
| Network analysis | Burp Suite | Insecure APIs, cleartext traffic, weak auth/session handling | M3, M4, M5 |
| Lab / target | Android emulator | Safe environment to run the apps | – |

## 2. Architecture
```
 APK ──► MobSF (static) ─┐
                         ├─► mastf.py ─► OWASP-mapped Markdown report
 Emulator ─► Frida ──────┤
 Emulator ─► Burp proxy ─┘  (manual findings added to report)
```

## 3. Split setup: Kali VM + Windows host
Static analysis runs in Kali (Docker is simpler there). The emulator and Frida run
on Windows (needs hardware acceleration, unreliable inside a VirtualBox VM).

### 3a. Kali VM — MobSF + mastf.py

**Install Docker:**
```bash
sudo apt update && sudo apt install -y docker.io
sudo systemctl enable --now docker
```

**If Docker can't resolve hosts (`i/o timeout` on `auth.docker.io`), fix DNS first:**
```bash
nmcli con show                       # find your connection name
sudo nmcli con mod "<connection name>" ipv4.dns "8.8.8.8 1.1.1.1" ipv4.ignore-auto-dns yes
sudo nmcli con up "<connection name>"
sudo systemctl restart docker
```
If `nmcli` doesn't help, as a fallback: `echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" | sudo tee /etc/resolv.conf`. If the VM has no internet at all (ping to `8.8.8.8` also fails), switch the VM's network adapter from Bridged to **NAT** in VirtualBox settings.

**Fix folder permissions before first run** (MobSF runs as UID 9901 inside the container, not root):
```bash
sudo chown -R 9901:9901 ~/.MobSF
```

**Run MobSF:**
```bash
sudo docker run -it --rm -p 8000:8000 -v ~/.MobSF:/home/mobsf/.MobSF opensecurity/mobile-security-framework-mobsf:latest
```
Leave this terminal open. Ready when it prints `Listening at: http://0.0.0.0:8000`. Open `http://127.0.0.1:8000`, default login `mobsf`/`mobsf`. Copy the REST API key from the terminal's `REST API Key:` line or the **API Docs** page.

**Set up mastf.py** (copy the project into Kali's own disk first if it's on a shared folder — venvs don't work on VirtualBox shared folders):
```bash
cp -r /media/sf_mastf ~/mastf   # if using a shared folder
cd ~/mastf
python3 -m venv venv
source venv/bin/activate
pip install requests jinja2
export MOBSF_URL=http://127.0.0.1:8000
export MOBSF_API_KEY=<paste the real key — no angle brackets, no quotes>
```

**Script fix applied:** the upload call now sets an explicit content type, which MobSF's upload endpoint requires:
```python
files={"file": (os.path.basename(path), f, "application/octet-stream")}
```

**Run a scan:**
```bash
python mastf.py scan ~/Downloads/InsecureBankv2.apk
```
Report lands in `~/mastf/reports/`. Variables set with `export` only last for that terminal tab — re-set them in any new tab.

**Target app:** use InsecureBankv2 (has a ready-made APK with releases, unlike DIVA which has source only):
```bash
git clone --depth 1 https://github.com/dineshshetty/Android-InsecureBankv2.git
```
Package name: `com.android.insecurebankv2`.

**Download the PDF report:**
```bash
curl -X POST http://127.0.0.1:8000/api/v1/download_pdf \
  -H "Authorization: $MOBSF_API_KEY" \
  -d "hash=<scan hash from Recent Scans page>" \
  -o ~/mastf/reports/InsecureBankv2_report.pdf
```

### 3b. Windows host — emulator + Frida (no Android Studio, to save disk space)

**Install Java and the command-line SDK tools** (not full Android Studio):
```
winget install EclipseAdoptium.Temurin.17.JDK
```
Download "Command line tools only" from the Android Studio download page. Extract so the path is exactly:
```
C:\Android\cmdline-tools\latest\bin\sdkmanager.bat
```
(the `latest` folder must directly contain `bin`/`lib` — a common mistake is missing that nesting level).

**Set PATH** (Environment Variables, User variables → Path → New, one entry per line):
```
C:\Android\cmdline-tools\latest\bin
C:\Android\platform-tools
C:\Android\emulator
```
Also add the Frida Scripts folder once installed (path shown below). Open a **new** Command Prompt after editing PATH — changes don't apply to windows already open.

**Install SDK pieces** (check free disk space first — need ~5 GB):
```
sdkmanager --licenses
sdkmanager "platform-tools" "emulator" "system-images;android-30;google_apis;x86_64" "extras;google;Android_Emulator_Hypervisor_Driver"
```
Use `google_apis`, not `google_apis_playstore` — Play images can't be rooted, and Frida needs root.

**Install the acceleration driver** (Administrator Command Prompt):
```
cd C:\Android\extras\google\Android_Emulator_Hypervisor_Driver
silent_install.bat
sc query aehd
```
Should say `RUNNING`. Needs VT-x/AMD-V on in BIOS. Check with `emulator -accel-check`.

**Create a small emulator** (to fit limited disk space):
```
avdmanager create avd -n test -k "system-images;android-30;google_apis;x86_64" -d pixel_5
```
Edit `C:\Users\<you>\.android\avd\test.avd\config.ini` and set:
```
disk.dataPartition.size=2G
hw.ramSize=2048
```
If the emulator fails with `Not enough space to create userdata partition`, this file still has the default (larger) size — fix it and launch with `-wipe-data` once.

**Start the emulator** (keep this window open and untouched while it runs):
```
emulator -avd test -no-snapshot -gpu swiftshader_indirect
```

**Install the app** (in a second Command Prompt):
```
adb devices
adb install "C:\path\to\InsecureBankv2.apk"
```

**Install Frida tools:**
```
pip install frida-tools
frida --version
```
If `pip install` succeeds but `frida` isn't recognized afterward, find the real path and add it to PATH permanently:
```
where /r C:\Users\<you> frida.exe
```
(With Store-installed Python, this is often buried under `AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_...\LocalCache\local-packages\Python313\Scripts`.)

**Download the matching frida-server** from `https://github.com/frida/frida/releases` — find the release tag matching your exact `frida --version` output, then under Assets download **only** the file named:
```
frida-server-<version>-android-x86_64.xz
```
⚠️ Do not confuse this with `frida-core-devkit` or `frida-gum-devkit` — those are C developer packages with completely different contents and will not run as a server. Extract the `.xz`, confirm you get **one single file** (tens of MB, no `<DIR>` in a `dir` listing), rename it to exactly `frida-server` with no extension.

**Push and start frida-server:**
```
adb root
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server &"
```
If `adb root` says "adbd is already running as root," you don't need `su -c` — just run the binary directly as shown above.

**Verify it's alive:**
```
frida-ps -U
```
Should list the emulator's running processes. **frida-server does not survive an emulator reboot** — re-run the push/start steps after any restart.

**If spawning the app fails with `Failed to spawn: need Gadget to attach on jailed Android`,** SELinux enforcement is blocking it. Set it to permissive (lab use only):
```
adb shell getenforce
adb shell setenforce 0
adb shell getenforce     # should now say Permissive
```

**Attach Frida to the app and relaunch it:**
```
cd "C:\path\to\mastf"
frida -U -f com.android.insecurebankv2 -l frida\storage_and_ssl.js
```
If it spawns paused, type `%resume`. Then interact with the app (tap **Autofill Credentials**, then **Login**) and watch for `[SharedPrefs]` and `[Logcat]` lines in the Frida terminal — that output is the evidence for the M9 (Insecure Data Storage) finding. A line like `NetworkSecurityConfig: No Network Security Config specified, using platform default` is evidence for M5 (Insecure Communication).

**Check local storage directly:**
```
adb pull /data/data/com.android.insecurebankv2 loot\insecurebankv2
findstr /si "password token secret" loot\insecurebankv2\*
```

**Set up Burp:**
1. Burp Proxy listener on `127.0.0.1:8080`.
2. Emulator settings → Wi-Fi → proxy → manual → `127.0.0.1:8080`.
3. Browse to `http://burp` in the emulator browser, download the CA cert, install it under Settings → Security.
4. A user-installed cert only works on apps targeting older Android versions without pinning — InsecureBankv2's own backend server (`AndroLabServer`, needs Python 2) is the best target for full HTTPS interception.

## 4. Vulnerability classes covered
- **Insecure data storage (M9):** credentials in SharedPreferences, SQLite, external storage, logs.
- **Broken authentication (M3):** exported activities reachable without login, weak/no server-side session checks, "Autofill Credentials" shipping a working test account inside the app.
- **Insecure APIs (M4/M5):** HTTP instead of HTTPS, missing Network Security Config, no cert pinning, IDOR, verbose errors.
- **Weak crypto (M10):** MD5/SHA1, ECB mode, hardcoded keys.

## 5. Common failure points (in order of how often they bite)
1. **PATH resets every new Command Prompt window** unless set permanently via Environment Variables — don't rely on `set PATH=...` alone.
2. **frida-server doesn't survive emulator reboots.** Re-push and restart it after every restart.
3. **Downloading the wrong Frida asset** (`frida-core-devkit` instead of `frida-server`) — check for "server" and your exact architecture in the filename, and confirm it's a single file after extracting, not a folder.
4. **VirtualBox shared folders can't host a Python venv** — copy the project to the VM's own disk first.
5. **Docker DNS failures in Kali** — fix with `nmcli` DNS override or switch the VM to NAT networking.
6. **MobSF upload needs an explicit content type** on the multipart file field, or it returns 400.
7. **SELinux enforcing mode blocks Frida's spawn-and-attach** on some emulator images — `adb shell setenforce 0` fixes it for lab use.

## 6. Deliverables for submission
Architecture diagram, screenshots (MobSF dashboard, Frida output showing SharedPrefs/logcat writes, Burp request/response), the generated Markdown + PDF report, a findings table with remediation, and a conclusion.

## 7. Remediation examples
- Store secrets in Android Keystore / EncryptedSharedPreferences.
- Enforce HTTPS via `networkSecurityConfig`, add certificate pinning.
- Set `android:exported="false"`, `android:allowBackup="false"`, `debuggable=false`.
- Do all authorization checks server-side.
- Use AES-GCM, SHA-256+, `SecureRandom`.

## 8. Ethics
Test only apps you own or have written permission for (InsecureBankv2, DIVA, DVIA-v2, the OWASP MASTG Hacking Playground are all built for this purpose). This is for learning.
