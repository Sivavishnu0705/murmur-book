# release_gate.py
"""Listing 31.3 — Python: the release gate. Runs in CI on the release branch,
AFTER the tests (Ch 25 Listing 25.6), and fails the release on any finding. It
checks the BUILT server binary, not just the source, because what ships is the
binary."""
import glob, os, re, subprocess, sys, tempfile

# files that go into a default (release) build
def go_files(server):
    out = []
    for f in glob.glob(os.path.join(server, "*.go")):
        head = open(f).read(200)
        if "//go:build lab" not in head and not f.endswith("_test.go"):
            out.append(f)
    return out

def check(server, platform_dirs):
    findings = []
    # 1. The release binary must not contain lab-only code.
    binary = os.path.join(tempfile.mkdtemp(), "murmur-server")
    subprocess.run(["go", "build", "-o", binary, "."], cwd=server, check=True,
        capture_output=True)
    syms = subprocess.run(["go", "tool", "nm", binary], capture_output=True,
        text=True).stdout
    for s in ("main.labAttestation", "main.(*Evil)", "main.runSelfTest",
        "main.newRoot", "lab-attestation"):
        if s in syms or s.encode() in open(binary, "rb").read():
            findings.append(f"release binary contains lab-only code: {s}")
    # 2. Source rules for shipped server code.
    rules_go = {r"InsecureSkipVerify:\s*true": "TLS verification disabled",
                r'"math/rand"': "math/rand in server code (use crypto/rand)",
        r'log\.Print.*(token|Authorization|secret|key)': "secret-looking "
        "value logged"}
    for f in go_files(server):
        src = open(f).read()
        for rx, why in rules_go.items():
            if re.search(rx, src):
                findings.append(f"{os.path.basename(f)}: {why}")
    # 3. Platform code and configuration.
    rules_app = {r'allowBackup="true"': "Android backup enabled",
                 r'cleartextTrafficPermitted="true"': "cleartext traffic "
                 "allowed",
                 r"checkServerTrusted\([^)]*\)\s*\{\s*\}": "trust-all "
                 "TrustManager",
                 r"ALLOW_ALL_HOSTNAME_VERIFIER|HostnameVerifier \{ _, _ -> "
                 r"true": "hostname verification disabled",
                 r"kSecAttrAccessibleAlways\b": "Keychain item readable "
                 "while locked and migratable",
                 r"NSAllowsArbitraryLoads": "ATS disabled",
                 r"murmur\.test|10\.0\.2\.2": "dev endpoint in shipped code",
                 r"Log\.[dviw]\(.*(token|key|plaintext)": "secret-looking "
                 "value logged"}
    for d in platform_dirs:
        for f in glob.glob(os.path.join(d, "**", "*.*"), recursive=True):
            if not f.endswith((".kt", ".swift", ".xml", ".plist")): continue
            src = open(f, errors="replace").read()
            for rx, why in rules_app.items():
                if re.search(rx, src):
                    findings.append(f"{os.path.relpath(f, d)}: {why}")
            # 4. The NSE must never display server-supplied text (red-team
            # finding RT-6).
            if "UNNotificationServiceExtension" in src and \
                "content.body = Self.placeholder" not in src:
                findings.append(
                    f"{os.path.basename(f)}: NSE may display the push's own "
                    f"text (RT-6)")
    return findings

if __name__ == "__main__":
    server, dirs = sys.argv[1], sys.argv[2:]
    f = check(server, dirs)
    for x in f: print(f"  FAIL  {x}")
    print(
        f"  release gate: "
        f"{'PASS' if not f else f'BLOCKED ({len(f)} findings)'}")
    sys.exit(1 if f else 0)
