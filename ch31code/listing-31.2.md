# Murmur release checklist (v1)

Every item has an owner and an automated check where one exists. The release is
blocked until every box is ticked or carries a signed, dated exception. "Gate" =
Listing 31.3; "CI" = Listing 25.6.

## Build and supply chain
- [ ] Release built from a tagged commit by CI, not on a laptop; build is
      reproducible (two runners, same hashes)
- [ ] Gate: release binaries contain no `lab`-tagged code (dev login, lab
      attestation, malicious mode)
- [ ] Debug-only trust (dev root, `<debug-overrides>`, dev pins) absent from
      release variants — Gate
- [ ] Lockfiles committed (`go.sum`, `Cargo.lock`, Gradle lockfile,
      `Package.resolved`); no floating versions
- [ ] `govulncheck`, `cargo audit` + `cargo vet`, OSV scan on Android/iOS
      dependencies: no unwaived findings
- [ ] SBOM generated and archived with the release
- [ ] Android: R8 on, `debuggable=false`, signing key in a hardware-backed
      store; iOS: no `get-task-allow`
- [ ] Ch 25 insecure-API lint: clean

## TLS and PKI (Ch 4–9)
- [ ] TLS 1.3 only at the edge and between services; no TLS 1.2 fallback on
      mobile endpoints
- [ ] SPKI pins = current intermediates + backup key from a second CA; pin-set
      expiry > 6 months away
- [ ] Certificate lifetimes: edge per WebPKI rules, services 30 days with
      automated renewal tested
- [ ] mTLS policy: every internal route has an allowlist; default deny tested
      (Ch 27 §27.7)
- [ ] CT monitoring alerts on any certificate issued for Murmur's names

## OAuth, OIDC and sessions (Ch 10–15)
- [ ] PKCE S256 required; `plain` rejected; codes single-use, ≤ 60 s
- [ ] Redirects: claimed HTTPS links verified (assetlinks / AASA); custom scheme
      only as documented fallback
- [ ] Access tokens 5 min, `at+jwt`, ES256, `device_id` + `cnf.jkt`; no Bearer
      fallback anywhere
- [ ] Refresh: rotation, reuse detection revokes the family, 30 d idle / 90 d
      absolute
- [ ] Step-up (`acr=phr`, ≤ 5 min) on `devices:enroll`, `devices:revoke`,
      `keys:write`
- [ ] Token signing keys in KMS/HSM; rotation job running; JWKS overlap ≥ token
      TTL + skew + cache TTL (Listing 31.1)
- [ ] Revocation feed reaches every API instance within 60 s (measured)

## End-to-end encryption (Ch 16–24, 29–30)
- [ ] Cross-implementation vectors pass: X3DH/PQXDH, ratchet, safety numbers,
      sealed sender, STREAM, MLS (CI)
- [ ] Suite `0x0002` required for new sessions; `0x0001` receive-only (rule V1)
- [ ] Bundles verified against AIK-signed device lists; device-list version
      never decreases (RT-4)
- [ ] Incoming messages only from devices in the sender's signed list (RT-3)
- [ ] Persistence ordering tests (crash at every point) pass on both platforms
- [ ] MLS: AS check on KeyPackages, Welcomes, commits; admin rule; merge only
      after DS 202
- [ ] Key transparency: client checks inclusion; own-account monitor alarms on
      unknown AIK/device (RT-7)

## Storage (Ch 28)
- [ ] SQLCipher everywhere; raw random keys; `secure_delete`; WAL/SHM protected
- [ ] Keystore / Keychain items `ThisDeviceOnly`, after-first-unlock; no
      backups, no device transfer
- [ ] Wipe deletes keys before files; tested by killing the app mid-wipe

## Push and notifications (Ch 21, 29)
- [ ] Payloads fixed and content-free; collapse keys; dead tokens dropped
- [ ] NSE / FCM handler never displays server-supplied text (RT-6); previews off
      by default on the lock screen
- [ ] APNs `.p8` and FCM service-account keys only in murmur-push's secret store

## Logging, privacy and abuse
- [ ] Logger allowlist enforced; log canary test (tokens, IPs, device IDs,
      plaintext) passes (Ch 27 §27.8)
- [ ] Retention: app logs 14 d, security events 90 d, edge IP logs 24 h —
      enforced by the log pipeline
- [ ] Rate limits configured per Table 31.2; abuse reports carry only
      user-submitted content

## Operations and response
- [ ] Incident playbooks (§31.5) rehearsed this quarter: CA key, token key,
      sender-cert key, user device, server breach
- [ ] Minimum supported client version set; old-client cutoff date announced
- [ ] External audit findings: all high/critical fixed and re-tested; report
      summary published
- [ ] Bug bounty scope and safe-harbour terms live
