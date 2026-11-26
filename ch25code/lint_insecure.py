# lint_insecure.py
"""Part of Listing 25.6 — Python: a deliberately simple lint for insecure APIs across Murmur's
languages. Regexes, not a parser: it finds candidates for review; `# lint-ok: <reason>` (or
`// lint-ok:`) on the same line records a reviewed exception. Exit code 1 on findings."""
import pathlib, re, sys

RULES = [
    # (id, file suffixes, regex, message)
    ("go-insecure-tls", (".go",), r"InsecureSkipVerify\s*:\s*true", "TLS verification disabled"),
    ("go-math-rand", (".go",), r'"math/rand"', "math/rand in non-test code: use crypto/rand"),
    ("go-bytes-equal-secret", (".go",), r"bytes\.Equal\([^)]*(mac|tag|sig|token|hash)", "variable-time compare of a secret: use crypto/subtle"),
    ("py-random", (".py",), r"^\s*import random|^\s*from random import", "random module: use secrets/os.urandom for keys"),
    ("py-eq-digest", (".py",), r"(hmac|digest|tag|mac)\w*\s*==|==\s*\w*(digest|tag|mac)\(", "== on a MAC/digest: use hmac.compare_digest"),
    ("kt-ecb", (".kt", ".java"), r'Cipher\.getInstance\("AES"\)|/ECB/', "AES with ECB (the default for \"AES\")"),
    ("kt-trust-all", (".kt", ".java"), r"X509TrustManager|HostnameVerifier\s*\{\s*_,\s*_\s*->\s*true", "custom trust manager / hostname verifier"),
    ("kt-sha1prng", (".kt", ".java"), r"SHA1PRNG", "SecureRandom.getInstance(\"SHA1PRNG\")"),
    ("kt-content-equals", (".kt",), r"(mac|tag|digest)\w*\.contentEquals\(", "variable-time compare: use MessageDigest.isEqual"),
    ("swift-accessible-always", (".swift",), r"kSecAttrAccessibleAlways\b", "Keychain item readable while locked and migratable"),
    ("swift-arbitrary-loads", (".plist", ".swift"), r"NSAllowsArbitraryLoads", "ATS disabled"),
    ("rust-unwrap-parse", (".rs",), r"tls_deserialize\([^)]*\)\.unwrap\(\)", "panics on attacker input"),
]

def is_test(p): return "test" in p.name or "_fuzz" in p.name or p.parent.name in ("tests", "testdata")

def scan(root):
    findings = []
    for p in sorted(pathlib.Path(root).rglob("*")):
        if not p.is_file() or "target" in p.parts or "out" in p.parts:
            continue
        for rid, suffixes, rx, msg in RULES:
            if p.suffix not in suffixes or (rid in ("go-math-rand", "py-random") and is_test(p)):
                continue
            for n, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
                if re.search(rx, line, re.I) and "lint-ok" not in line:
                    findings.append(f"{p.relative_to(root)}:{n}: [{rid}] {msg}")
    return findings

if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    f = scan(root)
    print("\n".join(f) if f else "no findings")
    print(f"{len(f)} finding(s)")
    sys.exit(1 if f else 0)
