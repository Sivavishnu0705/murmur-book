# Verification notes

What was run for each chapter, against which versions, and what the labs stand in for. The book prints a one-line summary in each chapter's "About the listings" note and the general conventions in Appendix E.11.

## Chapter 6

The Python key-schedule code in this chapter reproduces the official example values from RFC 8448 ("Example Handshake Traces for TLS 1.3") exactly. The handshake dissected in §6.2 and the lab is a real capture between the Go server in Listing 6.2 and a Go client, using Murmur's private PKI from Chapter 4. Message sizes and fields quoted in the text come from that capture.

## Chapter 7

The Go listings were run with Go 1.24 against Murmur's private PKI from Chapter 4. Go's `crypto/tls` does not implement 0-RTT for TLS over TCP, so the 0-RTT replay in the lab uses OpenSSL's test server, which supports early data and lets anti-replay protection be switched on and off. The Python HPKE listing uses the `cryptography` package. The output shown comes from running the listings as printed. The Kotlin and Swift notes were compiled and type-checked (Appendix E.2) but not run on a device; check them against current SDK documentation.

## Chapter 9

The Go listings were run with Go 1.24. The lab enrolls simulated Android and iOS devices: real attestations can only be produced by real hardware, so the lab generates attestation chains and App Attest objects with the same structure, signed by lab roots that stand in for Google's and Apple's. The verifiers check them exactly as they would check real ones, and point out where production verification adds steps (revocation lists, the real roots). The Kotlin listings were compiled against the Android SDK and the Swift listings type-checked against the iOS APIs they use (Appendix E.2), but none was run on a device; build and test them on real hardware, and check them against current SDK documentation. The lab output shown comes from running it as printed.

## Chapter 10

The Go resource server and its test driver, and the Python JWT listing, were run as printed, and the output shown is theirs. The Go code uses only the standard library so that every validation step is visible; in production, use a maintained JOSE/JWT library configured with the same rules. The lab uses Keycloak, an open-source authorization server, which you run yourself; its exact configuration screens and defaults change between versions.

## Chapter 11

The Go authorization-server code and the lab driver were run as printed, and the output shown is theirs. The Kotlin listings were compiled against the Android SDK (AppAuth's API checked against its source) and the Swift listings type-checked against the iOS APIs they use (Appendix E.2), but none was run on a device; platform APIs in this area (Custom Tabs, Auth Tab, `ASWebAuthenticationSession` callbacks) change frequently, so check current documentation.

## Chapter 12

The Go verifier, account-linking logic and lab driver were run as printed, against a test identity provider served over TLS; the output shown is theirs (the test server's port changes on each run). The Kotlin listings were compiled against the Android SDK and the Swift listings type-checked against the iOS APIs they use (Appendix E.2), but none was run on a device; build and test them on real hardware, and check them against current SDK documentation.

## Chapter 13

The Go verification middleware, refresh service and lab driver were run as printed; the output shown is theirs, and the JWK thumbprint code reproduces the example value in RFC 9449. The Kotlin listings were compiled against the Android SDK and the Swift listings type-checked against the iOS APIs they use (Appendix E.2), but none was run on a device; build and test them on real hardware, and check them against current SDK documentation.

## Chapter 14

Listing 14.3 uses the maintained `go-webauthn` library and was compiled and vetted against v0.15.0, the newest release that supports Go 1.24. Its API changes between releases, so check the listing against the version you use. To keep every check visible and testable, Listings 14.4 and 14.5 implement the same verification with the standard library (accepting only what Murmur accepts: ES256 credentials, `none` attestation, required user verification) and run it against a simulated authenticator; the output shown is theirs. The Kotlin listings were compiled against the Android SDK and the Swift listings type-checked against the iOS APIs they use (Appendix E.2), but none was run on a device; build and test them on real hardware, and check them against current SDK documentation.

## Chapter 15

The Go registry, refresh endpoint and lab driver were run as printed; the output shown is theirs (device IDs are random, so they change between runs). Token signing and DPoP verification are elided in these listings because Chapters 10 and 13 implement them. The Kotlin listings were compiled against the Android SDK and the Swift listings type-checked against the iOS APIs they use (Appendix E.2), but none was run on a device; build and test them on real hardware, and check them against current SDK documentation.

## Chapter 16

All listings are Python, using the `cryptography` package's real X25519, Ed25519, HKDF, HMAC, AES-GCM, ML-KEM and ML-DSA implementations; every listing was run as printed and the output shown is theirs (key fingerprints are random and change between runs). The **protocols** are toys built to be broken. Never deploy them.

## Chapter 17

The Python listings use the `noiseprotocol` package for the handshakes, and Listing 17.1 implements the specification's state machine directly so it can be read; the lab checks that the two produce **byte-identical** handshake messages and hashes. All Python listings were run as printed and the output shown is theirs (keys and codes are random). The Rust core in §17.6 was built with `snow` 0.10 and UniFFI 0.29.5 and tested with a full handshake whose six-digit code matches Listing 17.4's; the Kotlin and Swift calls were compiled and type-checked against the bindings UniFFI generated from it.

## Chapter 18

The Python listings (X3DH, XEdDSA, PQXDH and the lab) and the Go directory and test-vector check were run as printed, and the output shown is theirs. Test vectors use fixed keys and a fixed XEdDSA nonce so they are reproducible; everything else is random. The Go code is an **independent** implementation (Go's standard X25519, HKDF and Ed25519), and it reproduces the Python vectors exactly. The Kotlin and Swift initiators were run on the desktop JVM (with Tink) and with swift-crypto, and both reproduce `x3dh_vectors.json` with and without the one-time prekey. The protocols follow Signal's X3DH and PQXDH (revision 3) specifications, simplified where noted; production code should use libsignal (§18.8).

## Chapter 19

The Python ratchet, fuzz test and lab were run as printed, and the output shown is theirs. The test vectors use a fixed SK and a deterministic sequence of ratchet keys; everything else is random. The algorithm follows Signal's Double Ratchet specification; the KDF and encryption choices are Murmur's and noted where they differ from the specification's recommendations. The Kotlin and Swift persistence listings were compiled and type-checked (Appendix E.2) but not run on a device; build and test them on real hardware.

## Chapter 20

The Go device-list service and lab, the Python safety-number code and the key-transparency sketch were run as printed, and the output shown is theirs. The safety-number implementation reproduces a published libsignal test vector exactly. The key-transparency code illustrates the concepts (signed tree heads, inclusion proofs, split-view detection) and is not a deployable design. The Kotlin and Swift listing was compiled and type-checked (Appendix E.2) but not run on a device.

## Chapter 21

The Go relay, sealed-sender code and lab, and the Python attachment code were run as printed, and the output shown is theirs. The sealed-sender design is a simplified version of Signal's. The Swift Notification Service Extension and Kotlin FCM handler were type-checked and compiled (Appendix E.2) but not run on a device; build and test them on real hardware.

## Chapter 22

The Python sender-keys implementation and lab, and the Go group-membership service and lab, were run as printed, and the output shown is theirs. Pairwise channels are simulated (in Murmur they are the Double Ratchet sessions of Chapter 19).

## Chapter 23

The Rust lab uses **OpenMLS 0.7.4** (with `openmls_rust_crypto` 0.4.4) and was compiled and run as printed; the sizes and results shown are its output. The UniFFI wrapper (Listing 23.4) was compiled with UniFFI 0.29.5, its Rust test passes, and Kotlin and Swift bindings were generated from it; the Kotlin and Swift calling code (Listing 23.5) was compiled (Kotlin) and type-checked (Swift) against the bindings UniFFI generated from it, but not run on a device. The Go delivery service and its lab were run as printed.

## Chapter 24

The Go identity-key upload service, context registry and lab driver were run as printed against a real TLS 1.3 server, and the output shown is theirs. XEdDSA signing for the lab client is a small, non-constant-time Go port of Chapter 18's algorithm (checked against Go's standard Ed25519 verification); production clients sign in the Rust core with libsignal.

## Chapter 25

The Go fuzz tests, the Hypothesis state-machine test, the lab, the timing measurement, the lint and the executable cross-check of the formal model's flaw were all run as printed, and the output shown is theirs. The **ProVerif model (Listing 25.3)** is printed with the results it should produce; run it yourself to confirm them (stretch exercise 3). Listing 25.4 demonstrates the same flaw with executable code. The CI pipeline (Listing 25.6) is a configuration file to adapt to your own repository.

## Chapter 26

The Protocol Buffers schema (Listing 26.1) was compiled with `protoc` (via `grpc_tools`), and a sample envelope was encoded and decoded; the output shown is theirs. The Rust UniFFI interface (Listing 26.2) was built with `cargo build` against UniFFI 0.29; its method bodies are `unimplemented!()` on purpose, because the implementations come in Chapters 27–30. The lab (Listing 26.4) boots the four Murmur services in one Go process with real TLS 1.3 and mTLS, and the output shown is its own. The **`docker-compose.yml` (Listing 26.3)** is an optional alternative to the one-process lab and is not part of the book's tested code; check it against your Docker Compose version. Its `pki-init` step assumes the Chapter 4 PKI tool has been extended with an edge CA, as the lab's `devpki.go` does.

## Chapter 27

The output shown comes from running the code as printed:
- **The Go server** (Listings 27.1–27.5 and 27.7–27.12) was built with Go 1.24, standard library only, and serves the lab over real TLS 1.3 and mTLS.
- **The Python clients** (Listings 27.13–27.14) drive it using the Chapter 18, 19 and 21 code and the Chapter 26 protobuf schema.
- **The SQL** (`queries.sql`) was run against **PostgreSQL 16.15** from 25–80 concurrent connections (Listing 27.6).
- **The MLS framing parser** (Listing 27.8) was tested against messages produced by **OpenMLS 0.7**.

What the lab replaces, and why:
- **The lab runs on the in-memory store, not on Postgres.** The Go Postgres store (Listing 27.5) compiles and passes `go vet`, but it needs a Postgres driver of your choice (for example `pgx`) to run. The in-memory store gives the same guarantees, and the SQL that `PGStore` embeds is exactly the file the concurrency tests in Listing 27.6 ran.
- **Apple's and Google's push services were not contacted.** The lab replaces them with local HTTP/2 endpoints that verify the provider credentials as APNs and FCM do and record what each provider would see.
- **Attestation is a lab stand-in.** A lab key signs the evidence instead of Play Integrity or App Attest (Ch 9 has the real verifiers).
- **murmur-auth's login is a dev stand-in.** It trusts the account name in the request and stands in for the browser, PKCE and passkey flows of Chapters 11–14.
- **Two protections are left out of the lab.** Python's `ssl` module cannot export TLS keying material, so the Chapter 24 channel binding on identity-key uploads is not enforced; Chapter 24's Go lab tests it. Sealed-sender certificates are unsigned; Chapter 29 adds the signature check.

## Chapter 28


**Platform code.** The Kotlin and Swift listings (28.1, 28.2, 28.4–28.7, 28.9, 28.10, 28.12, 28.13) were compiled (Kotlin, against the Android SDK) and type-checked (Swift) against the platform APIs and the bindings UniFFI generated from the Rust core (Appendix E.2), but not run on a device. Treat them as reference implementations to build and test on real hardware. The Android backup rules (Listing 28.6, continued) were checked as well-formed XML only.

**What ran, with the output shown:**
- **Listing 28.1 (test)**, a Python port of the Kotlin `derToRaw`, ran against 2,000 real P-256 signatures and nine malformed inputs.
- **Listing 28.3, the Rust core's identity-key creation**, was built and its test run with `cargo test` (x25519-dalek 2, zeroize, UniFFI 0.29).
- **Listing 28.8, the storage stack model**, ran on **SQLCipher 4.12** through `sqlcipher3`. Its hardware key is a stand-in: an AES-256-GCM key kept in a separate directory. Real hardware never releases its key, so the stand-in shows the data flow, not the hardware's protection.
- **Listing 28.11, the client key lifecycle**, ran as part of the lab, against the Chapter 27 server with one addition from this chapter: Listing 28.14, idempotency keys, plus a prekey count route and duplicate-ID protection.
- **Listing 28.15, the lab**, ran against that server with the Chapter 18, 19 and 26 code.

## Chapter 29


**Platform code.** The Kotlin and Swift listings (29.3–29.6, 29.9, 29.10, 29.12) were compiled (Kotlin) and type-checked (Swift) against the platform APIs and the bindings generated from the murmur-core interface printed before Listing 29.3 (Appendix E.2), but not run on a device. Build and test them on real hardware.

**What ran, with the output shown:**
- **The JDK calls in Listing 29.5:** its cipher code was run on a real JDK and cross-checked against Python's Listing 21.4 in both directions, at seven sizes from 0 bytes to 1 MB.
- **The executable model** (Listings 29.2, 29.7, 29.11 and the lab, Listing 29.13) ran on SQLCipher 4.12 through the Chapter 28 storage model, against the Chapter 27–28 server with this chapter's additions:
  - sender certificates (Listing 29.1);
  - resumable attachment uploads (Listing 29.8);
  - an AIK lookup and replacement rule;
  - a relay fan-out check based on the signed device list.
- **The race between the app and its notification extension** used two real operating-system processes on one database file.

**Stand-ins in the lab:** the hardware keys are Chapter 28's stand-in, and token refresh is replaced by a fresh dev login.

## Chapter 30


**What ran, with the output shown:**
- **The Rust core (Listing 30.1)** was built against OpenMLS 0.7.4 and UniFFI 0.29.5.
- **Its bindings** were generated for Kotlin, Swift and Python. The method lists of the generated Kotlin and Swift APIs are printed below.
- **The lab (Listing 30.7)** calls the real Rust library through the generated **Python** bindings. The group service (Listing 30.2) supplies the core's three callbacks over real SQLCipher.
- **The server additions** (Listings 30.5 and 30.4) were built with Go 1.24 and serve the lab.
- **The cost table (Listing 30.6)** is the output of a release build on a reference x86-64 machine.

**Platform code:** the Kotlin and Swift group services (Listing 30.3) were compiled (Kotlin, with SQLCipher for Android) and type-checked (Swift, with GRDB) against the bindings UniFFI generated from Listing 30.1 (Appendix E.2), but not run on a device. Build and test them on real hardware.

## Chapter 31


**What ran, with the output shown:**
- **The threat-model status board (Fig 31.1)** is printed by a small script from a YAML file. The script also enforces the release rule for threats.
- **The token-key rotation job (Listing 31.1)** was built with Go 1.24. A driver runs it through 75 simulated days, including an emergency rotation.
- **The release gate (Listing 31.3)** builds the real server binary and inspects its symbols, then scans the platform code from Chapters 28–31. It ran twice: against the Chapter 30 tree, where it blocks the release, and against this chapter's fixes, where it passes.
- **The red-team lab (Listings 31.4–31.7)** runs against the real Chapter 27–31 server in its `lab` build. The clients are the Python models of the Chapter 29 clients, over real TLS, DPoP and SQLCipher. The intercepting proxy is real and decrypts real TLS.

**Platform code:** the Swift fix in Listing 31.8 was applied to Listing 29.9 with `patch` and the result type-checked (Appendix E.2); it was not run on a device. The lab checks the same logic in the modelled Notification Service Extension, and the release gate checks that the Swift file contains the fix. The checklist (Listing 31.2) is a document; its automated items point to the listings that check them.

## Chapter 32


**What ran, with the output shown:**
- **The cryptographic inventory (Listing 32.1)** scans the real Murmur code from Chapters 28–31 and prints a priority list. Its first run found a gap, shown in the lab.
- **The TLS measurement (Listing 32.2)** runs real TLS 1.3 handshakes with Go 1.24's X25519MLKEM768 on loopback, and reads the chosen group out of the ServerHello bytes.
- **The size budget (Listing 32.3)** measures ML-KEM and ML-DSA with Python's `cryptography` package. It builds real ML-DSA X.509 chains and verifies them, and rebuilds Murmur's signed structures with hybrid signatures.

**Not code:** the evaluation checklist (Listing 32.4) is a document. Timings come from one reference x86-64 machine and are only meaningful as ratios.
