#!/usr/bin/env python3
"""
MASTF - Mobile Application Security Testing Framework (educational)
Orchestrates: MobSF static analysis -> OWASP Mobile Top 10 mapping -> report.
Use ONLY on apps you own or intentionally vulnerable training apps
(InsecureBankv2, DIVA, OWASP MASTG Hacking Playground, DVIA-v2).

Usage:
  export MOBSF_URL=http://127.0.0.1:8000
  export MOBSF_API_KEY=<key shown on MobSF home page>
  python mastf.py scan path/to/app.apk
"""
import os, sys, json, datetime, requests

MOBSF_URL = os.environ.get("MOBSF_URL", "http://127.0.0.1:8000")
API_KEY = os.environ.get("MOBSF_API_KEY", "")
HEADERS = {"Authorization": API_KEY}

# Map MobSF finding keywords -> OWASP Mobile Top 10 (2024)
OWASP_MAP = {
    "M1: Improper Credential Usage":      ["hardcoded", "api key", "password", "secret", "token"],
    "M2: Inadequate Supply Chain Security": ["third party", "sdk", "library"],
    "M3: Insecure Authentication/Authorization": ["exported", "biometric", "auth", "permission"],
    "M4: Insufficient Input/Output Validation": ["sql", "injection", "webview", "javascript"],
    "M5: Insecure Communication":         ["cleartext", "ssl", "tls", "certificate", "http://"],
    "M6: Inadequate Privacy Controls":    ["pii", "location", "contacts", "sms"],
    "M7: Insufficient Binary Protections": ["obfuscat", "root detection", "debuggable", "tamper"],
    "M8: Security Misconfiguration":      ["backup", "debuggable", "cleartexttraffic", "manifest"],
    "M9: Insecure Data Storage":          ["sharedpreferences", "world readable", "external storage", "sqlite", "log"],
    "M10: Insufficient Cryptography":     ["md5", "sha1", "des", "ecb", "weak crypto", "random"],
}

def upload(path):
    with open(path, "rb") as f:
        r = requests.post(f"{MOBSF_URL}/api/v1/upload", headers=HEADERS,
                          files={"file": (os.path.basename(path), f)})
    r.raise_for_status()
    return r.json()          # contains 'hash', 'scan_type', 'file_name'

def scan(meta):
    r = requests.post(f"{MOBSF_URL}/api/v1/scan", headers=HEADERS, data=meta)
    r.raise_for_status()
    return r.json()

def classify(text):
    text = text.lower()
    return [cat for cat, kws in OWASP_MAP.items() if any(k in text for k in kws)] or ["Unmapped"]

def extract_findings(report):
    findings = []
    # Manifest issues
    for item in report.get("manifest_analysis", {}).get("manifest_findings", []):
        findings.append({"title": item.get("title", ""), "severity": item.get("severity", "info"),
                         "detail": item.get("description", ""), "source": "manifest"})
    # Code analysis
    for rule, item in report.get("code_analysis", {}).get("findings", {}).items():
        meta = item.get("metadata", {})
        findings.append({"title": rule, "severity": meta.get("severity", "info"),
                         "detail": meta.get("description", ""), "source": "code"})
    # Hardcoded secrets
    for s in report.get("secrets", []) or []:
        findings.append({"title": "Hardcoded secret", "severity": "high",
                         "detail": str(s)[:200], "source": "secrets"})
    for f in findings:
        f["owasp"] = classify(f["title"] + " " + f["detail"])
    return findings

def write_report(app, findings):
    os.makedirs("reports", exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"reports/{app}_{stamp}.md"
    order = {"high": 0, "warning": 1, "medium": 1, "info": 2, "good": 3, "secure": 3}
    findings.sort(key=lambda x: order.get(x["severity"].lower(), 2))
    with open(out, "w") as f:
        f.write(f"# Security Report - {app}\nGenerated: {stamp}\n\n")
        f.write(f"Total findings: {len(findings)}\n\n## Findings\n\n")
        f.write("| Severity | Title | OWASP Mobile Top 10 | Source |\n|---|---|---|---|\n")
        for x in findings:
            f.write(f"| {x['severity']} | {x['title']} | {', '.join(x['owasp'])} | {x['source']} |\n")
    return out

def main():
    if len(sys.argv) != 3 or sys.argv[1] != "scan":
        sys.exit(__doc__)
    apk = sys.argv[2]
    print("[1/4] Uploading to MobSF..."); meta = upload(apk)
    print("[2/4] Running static analysis (takes a minute)..."); report = scan(meta)
    print("[3/4] Mapping findings to OWASP Mobile Top 10..."); findings = extract_findings(report)
    print("[4/4] Writing report...");  path = write_report(os.path.basename(apk), findings)
    print(f"Done -> {path}  ({len(findings)} findings)")

if __name__ == "__main__":
    main()
