# PatchVerify

Verify whether a software update actually fixed what it promised.

> **"Updated ≠ Secure"** — PatchVerify independently confirms patch effectiveness using CVE intelligence, file-level diff analysis, and behavioral probing.

---

## Requirements

| Requirement | Minimum |
|---|---|
| Python | 3.8+ |
| pip | Latest |
| Node.js + npm | Any LTS (for npm package probing) |
| Git | Any |
| Internet | Required (NVD, OSV.dev, GitHub APIs) |

---

## Installation

### Windows (CMD)

```cmd
git clone https://github.com/Samudinimasha/patchverify.git
cd patchverify
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### Mac / Linux

```bash
git clone https://github.com/Samudinimasha/patchverify.git
cd patchverify
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

> **Every time you open a new terminal**, activate the virtual environment first:
> - Windows: `.venv\Scripts\activate`
> - Mac/Linux: `source .venv/bin/activate`

---

## First-Time Setup

Run once after installation to register your device via email OTP:

```cmd
patchverify --setup
```

You will be asked for your email and SMTP credentials. Gmail users need an **App Password** (not your normal password) — generate one at myaccount.google.com → Security → App Passwords.

---

## All Commands

```cmd
REM First-time device registration
patchverify --setup

REM Run a scan (--app, --old, --new are required)
patchverify --app django --old 4.1.0 --new 4.2.0

REM Skip behavioral probing (faster)
patchverify --app requests --old 2.28.0 --new 2.31.0 --no-probe

REM Output results as JSON
patchverify --app pillow --old 9.5.0 --new 10.0.0 --json

REM Provide a GitHub token to avoid API rate limits
patchverify --app flask --old 2.3.0 --new 3.0.0 --token YOUR_GITHUB_TOKEN

REM View past scan history
patchverify --history

REM Start web dashboard (then open http://localhost:8080)
patchverify --serve

REM Show help
patchverify --help
```

### Flag Reference

| Flag | Description |
|---|---|
| `--app` | Package name to scan |
| `--old` | Older / vulnerable version |
| `--new` | Newer / patched version |
| `--no-probe` | Skip behavioral testing (faster) |
| `--json` | Print results as raw JSON |
| `--token` | GitHub API token (optional, prevents rate limiting) |
| `--history` | Show all past scans with risk scores |
| `--serve` | Start the local web dashboard at http://localhost:8080 |
| `--setup` | Re-run first-time email OTP registration |

---

## Example Scans

### Python Packages (PyPI)

```cmd
REM Image processing — buffer overflow CVEs
patchverify --app pillow --old 9.5.0 --new 10.0.0

REM Web framework — SQL injection, XSS fixes
patchverify --app django --old 4.1.0 --new 4.2.0
patchverify --app django --old 3.2.0 --new 3.2.18

REM HTTP library — security fixes
patchverify --app requests --old 2.28.0 --new 2.31.0

REM Cryptography — critical CVEs
patchverify --app cryptography --old 41.0.0 --new 41.0.6

REM YAML parser — remote code execution fixes
patchverify --app pyyaml --old 5.4.0 --new 6.0.1

REM XML parser — XXE injection fixes
patchverify --app lxml --old 4.9.1 --new 4.9.3

REM SSH library — authentication bypass fixes
patchverify --app paramiko --old 3.0.0 --new 3.4.0

REM PDF library — parsing vulnerabilities
patchverify --app pypdf2 --old 2.12.0 --new 3.0.0

REM Scientific computing — memory issues
patchverify --app numpy --old 1.24.0 --new 1.26.0

REM Web framework — many CVEs
patchverify --app flask --old 2.3.0 --new 3.0.0
```

### Node.js Packages (npm)

```cmd
REM Prototype pollution — famous CVE
patchverify --app lodash --old 4.17.20 --new 4.17.21

REM HTTP client — SSRF vulnerability
patchverify --app axios --old 1.3.0 --new 1.6.0

REM Web framework — path traversal fixes
patchverify --app express --old 4.18.1 --new 4.18.2

REM JSON parsing — ReDoS vulnerability
patchverify --app minimist --old 1.2.5 --new 1.2.8

REM Markdown parser — XSS fixes
patchverify --app marked --old 9.0.0 --new 11.0.0

REM Template engine — injection fixes
patchverify --app ejs --old 3.1.8 --new 3.1.10

REM WebSockets — DoS vulnerability
patchverify --app ws --old 8.13.0 --new 8.17.0

REM Path handling — path traversal
patchverify --app path-to-regexp --old 6.2.0 --new 6.3.0
```

### Fast Scans (no probing)

```cmd
patchverify --app pillow --old 9.5.0 --new 10.0.0 --no-probe
patchverify --app cryptography --old 41.0.0 --new 41.0.6 --no-probe
patchverify --app lodash --old 4.17.20 --new 4.17.21 --no-probe
patchverify --app axios --old 1.3.0 --new 1.6.0 --no-probe
```

### JSON Output

```cmd
patchverify --app pillow --old 9.5.0 --new 10.0.0 --json
patchverify --app django --old 4.1.0 --new 4.2.0 --json
patchverify --app lodash --old 4.17.20 --new 4.17.21 --json
```

---

## Web Dashboard

```cmd
patchverify --serve
```

Then open your browser and go to: **http://localhost:8080**

Leave the CMD/terminal window running while using the browser. Press `Ctrl+C` to stop.

---

## Scope and Limitations

PatchVerify works **only on open-source packages** with publicly accessible source code.

| Type | Supported | Verification Depth |
|---|---|---|
| PyPI packages (pip) | ✅ Yes | CVE + File Diff + Behavioral Probe |
| npm packages (Node.js) | ✅ Yes | CVE + File Diff + Behavioral Probe |
| Open source Linux tools | ✅ Partial | CVE + File Diff only |
| Closed-source apps (Snapchat, WhatsApp, Zoom, Android Studio, Nessus) | ❌ No | Out of scope — no public source |
| Mobile apps (APK/IPA) | ❌ No | Out of scope |
| Compiled binaries (.exe) | ❌ No | Out of scope |

---

## Features

- 🔍 Per-promise patch verification — each claimed fix independently assessed
- 📊 Confidence scoring per CVE (0–100%) + overall risk score
- 🗄️ CVE intelligence from NVD API v2 and OSV.dev
- 📂 SHA-256 file-level diff confirms which modules actually changed
- 🧪 Behavioral probing for Python and Node.js packages at runtime
- 🌐 Live web dashboard at http://localhost:8080 with scan history
- 📧 Email notifications on scan completion
- 🔐 One-time email OTP device registration with JWT token

---

## Verdicts

Each CVE promise gets one of three verdicts:

| Verdict | Meaning |
|---|---|
| ✅ FIXED | CVE version range, file diff, and/or probe confirm the fix was delivered |
| ❌ NOT FIXED | Evidence shows the fix was not effectively applied |
| ⚠️ UNCONFIRMED | Insufficient data to confirm either way |

---

## License

MIT License
