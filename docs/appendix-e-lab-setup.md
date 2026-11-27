# Appendix E: Lab Environment Setup

---

> This is Appendix E of *Murmur* (Volumes 1 and 2), maintained here so it can be updated between printings. Section numbers match the ones the book cites.

This appendix explains how to set up a machine to run the book's labs. It has two kinds of content:

- **Principles that don't age:** how to isolate a lab, how to trust a development CA without weakening release builds, how emulators and simulators reach local services.
- **The exact versions used for the book**, with the commands that ran them, so you can reproduce the printed output.

Every listing is in the book's companion repository, **github.com/Sivavishnu0705/murmur-book**, in a directory named after its chapter (`ch27code/`, `ch30code/`, …) and under the file name in its first-line comment; each listing's **Code:** line gives the exact path. Clone it rather than copying listings by hand. Each chapter's "About the listings" note says what is particular to that chapter; E.11 gives the conventions for the rest. The commands below assume the repository's layout, run from its root. Its `scripts/check.sh` runs every listing that needs no phone: the Python and Go listings, the Part V labs against their chapter's server, the Rust crates, and the Chapter 30 lab and Chapter 31 red team on the Rust core.

---

## E.1 Principles

1. **Isolate the lab.** Use a separate user account, VM or container host. Lab servers run with test keys, development CAs and, in Chapter 31, a deliberately malicious mode. None of these belong near real accounts.
2. **Never weaken release builds to make labs work.** Development trust goes into debug-only configuration: Android `<debug-overrides>`, a Debug build configuration on iOS, the `lab` build tag on the server. The release gate (Ch 31) checks that it stays there.
3. **Use names, not IP addresses.** TLS verification checks hostnames. Labs use names under `.test` (`api.murmur.test`, `auth.murmur.test`), a TLD reserved by RFC 6761 so it will never resolve on the public internet.
4. **One development root, generated locally, never shared.** Each reader generates their own root with the Chapter 4 tool. Don't download a "lab root" from anyone, including this book.
5. **Record versions.** Write down the toolchain and library versions next to every result you keep. Most "it worked yesterday" failures are version changes.
6. **Key logging is opt-in per run.** `SSLKEYLOGFILE` lets Wireshark decrypt your lab traffic. Set it for one command at a time and delete the file afterwards (Ch 26 §26.6).

## E.2 Versions used for this book

**Verified:** these versions ran the labs whose output is printed in Chapters 25–32 and the appendices. Earlier chapters used the same or slightly older versions of the same tools.

| Component | Version | Used for |
|---|---|---|
| Go | 1.24.7 | Servers, TLS labs, release gate, rotation job |
| Rust / Cargo | 1.97.0 | Murmur core (OpenMLS + UniFFI) |
| OpenMLS | 0.7.4 (with `openmls_rust_crypto` 0.4) | Groups (Ch 30) |
| UniFFI | 0.29.5 | Kotlin/Swift/Python bindings |
| x25519-dalek / ed25519-dalek / curve25519-dalek | 2.0.1 / 2.2.0 / 4.1.3 | Core identity binding |
| aes-gcm / zeroize | 0.10.3 / 1.9.2 | Core |
| Python | 3.13.18 | Client models, labs, tools |
| `cryptography` | 50.0.1 (wheel bundling OpenSSL 4.0.2) | X25519/Ed25519/XEdDSA, ML-KEM, ML-DSA, X.509 |
| `sqlcipher3` | SQLCipher 4.12.0 community | Encrypted client storage (Ch 28–30) |
| `protobuf` (Python) | 7.36.1 | Envelope encoding |
| `psycopg` | 3.3.9 | PostgreSQL tests |
| PyYAML | 6.0.3 | Threat-model tooling (Ch 3, 31) |
| `noiseprotocol` | 0.3.1 | Noise handshakes (Ch 17) |
| Hypothesis / pytest | 6.170.17 / 9.1.1 | Property-based tests (Ch 25) |
| `grpcio-tools` | 1.85.4 | Compiling the protobuf schema (Ch 26, Appendix C) |
| PostgreSQL | 16.15 | Server store (Ch 27) |
| OpenJDK | 21.0.13 | Single-file Java checks |
| OpenSSL CLI | 3.0.13 | Certificate inspection |

**Mobile toolchains.** The Kotlin listings were compiled with Kotlin 2.2 against the Android 16 (API 36) SDK; OkHttp 4.12, Tink, AndroidX Credentials, `androidx.sqlite` and SQLCipher for Android were built from their sources, the UniFFI bindings were generated from the Rust crates, and the remaining library APIs (WorkManager, Room, Firebase Messaging, Play Integrity, AppAuth, Google ID) were checked against their published signatures. The Swift listings were type-checked with Swift 6.0 against CryptoKit's API (swift-crypto 3.15), GRDB 7.8 and the generated UniFFI bindings, with the Apple-only frameworks (Security, AuthenticationServices, DeviceCheck, UserNotifications, BackgroundTasks) checked against their published signatures; Listing 2.11's envelope and Listing 18.5's X3DH were also run and reproduce the Python test vectors.

**Other tools** (Android Studio, the Android NDK and emulator, Xcode and the iOS Simulator, Docker, Wireshark, and mitmproxy): the steps below describe the standard procedures. Use the current stable versions, and expect small differences in menus and flags.

## E.3 Python environment

```bash
python3 -m venv ~/murmur-venv && . ~/murmur-venv/bin/activate
pip install "cryptography==50.0.1" "protobuf==7.36.1" "psycopg[binary]==3.3.9" \
    "pyyaml==6.0.3" sqlcipher3-binary \
    "noiseprotocol==0.3.1" "hypothesis==6.170.17" "pytest==9.1.1" \
        "grpcio-tools==1.85.4"
python3 - <<'EOF'
# fails if the backend lacks PQ
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa
import sqlcipher3; print(sqlcipher3.connect(":memory:").execute(
    "pragma cipher_version").fetchone())
EOF
```

If the import fails, your `cryptography` was built against a backend without ML-KEM and ML-DSA (Appendix B). Install the PyPI wheel rather than a distribution package. `sqlcipher3-binary` bundles SQLCipher. If you build `sqlcipher3` from source instead, install the SQLCipher development headers first.

## E.4 Go

Install Go from the official distribution and check `go version`. The book's modules declare `go 1.24` and use only the standard library, so no module downloads are needed. That matters on networks where the module proxy is blocked.

```bash
cd ch31code/server
# lab build: dev login, lab attestation, malicious mode
go build -tags lab -o /tmp/murmur-lab .
# release build: refuses to start without production services
go build -o /tmp/murmur-server .
go vet ./... && gofmt -l .
```

Later Go releases also work. Go 1.26 changed key-generation functions to ignore a caller-supplied random source; tests that need determinism must use `testing/cryptotest.SetGlobalRandom` (Appendix B).

## E.5 PostgreSQL (local, no Docker)

The Chapter 27 tests expect PostgreSQL on port 55432, with a database and role named `murmur`:

```bash
PG=/usr/lib/postgresql/16/bin                 # adjust to your installation
# lab only: trust auth on localhost
$PG/initdb -D ~/murmur-pg -U murmur --auth=trust
$PG/pg_ctl -D ~/murmur-pg -o "-p 55432 -k /tmp" -l ~/murmur-pg/log start
$PG/createdb -h 127.0.0.1 -p 55432 -U murmur murmur
export MURMUR_PG="host=127.0.0.1 port=55432 user=murmur dbname=murmur"
python3 ch27code/pgtest/pg_concurrency.py
```

`trust` authentication is acceptable only because the server listens on localhost in a lab. Chapter 26's compose file (Listing 26.3) uses a password from a Docker secret instead.

## E.6 The Rust core and its bindings

```bash
cd ch30code/core
cargo build --release
# Python bindings (what the labs use)
cargo run --bin uniffi-bindgen -- generate --library \
    target/release/libmurmur_groups.so --language python --out-dir py
# Kotlin and Swift bindings (for the apps)
cargo run --bin uniffi-bindgen -- generate --library \
    target/release/libmurmur_groups.so --language kotlin --out-dir \
        bindings/kotlin
cargo run --bin uniffi-bindgen -- generate --library \
    target/release/libmurmur_groups.so --language swift  --out-dir \
        bindings/swift
# supply-chain checks (Ch 31); install with `cargo install cargo-audit
# cargo-vet`
cargo audit && cargo vet
```

On macOS the library is `libmurmur_groups.dylib`. Generating bindings from the compiled library (`--library`) keeps them in sync with exactly the code that was built.

### Android packaging

1. Install the NDK through Android Studio's SDK Manager, then `cargo install cargo-ndk`, then `rustup target add aarch64-linux-android x86_64-linux-android`.
2. Build for a device and the emulator, straight into the app's `jniLibs`:
   ```bash
   cargo ndk -t arm64-v8a -t x86_64 -o ../android/app/src/main/jniLibs build --release
   ```
3. Copy the generated Kotlin file into `app/src/main/java/…`. UniFFI's Kotlin bindings load the library through JNA, so add the JNA AAR to Gradle (`implementation("net.java.dev.jna:jna:<version>@aar")`).
4. Keep R8 from renaming the binding classes that JNA reaches by reflection. Add a keep rule for the generated package and for `com.sun.jna.**`.
5. Check that the APK contains `lib/arm64-v8a/libmurmur_groups.so` (`unzip -l app-release.apk | grep murmur`).

### iOS packaging

1. `rustup target add aarch64-apple-ios aarch64-apple-ios-sim` (add `x86_64-apple-ios` for Intel Macs).
2. Build static libraries for the device and the simulator:
   ```bash
   cargo build --release --target aarch64-apple-ios
   cargo build --release --target aarch64-apple-ios-sim
   ```
3. Put the generated `murmur_groupsFFI.h` and its `module.modulemap` in a `headers/` directory, and create an XCFramework:
   ```bash
   xcodebuild -create-xcframework \
     -library target/aarch64-apple-ios/release/libmurmur_groups.a     -headers headers \
     -library target/aarch64-apple-ios-sim/release/libmurmur_groups.a -headers headers \
     -output MurmurGroupsFFI.xcframework
   ```
4. Wrap it in a Swift package: a `.binaryTarget` for the XCFramework, and a regular target containing the generated `murmur_groups.swift` that depends on it. The app and its Notification Service Extension both depend on the package.
5. Mind the extension's memory budget (Ch 29, 30). Link the same static library into the extension, and avoid MLS operations there.

## E.7 Local PKI and trust

Generate the development PKI with the Chapter 4 tool, which creates a root, intermediates and short-lived leaves:

```bash
cd tools/murmurpki && go run . issue -out ~/murmur-pki -dev-edge-domain \
    murmur.test
# record this fingerprint
openssl x509 -in ~/murmur-pki/root.pem -noout -subject -fingerprint -sha256
```

Make the development root trusted **only where it should be**:

| Where | How | Scope |
|---|---|---|
| Go and Python lab clients | Pass the root explicitly (`RootCAs`, `cafile=`) | That process only |
| Android debug build | Copy the root to `app/src/debug/res/raw/murmur_dev_root.pem`. Reference it from `<debug-overrides><trust-anchors><certificates src="@raw/murmur_dev_root"/></trust-anchors></debug-overrides>` in the network security config | Debuggable builds only; ignored in release |
| iOS Simulator | `xcrun simctl keychain booted add-root-cert ~/murmur-pki/root.pem` | That simulator only |
| Real test devices | Avoid. If you must, use a dedicated test device and remove the root afterwards | — |

Never install the development root in your desktop's system trust store.

## E.8 Networking: emulators and simulators to local services

**Android emulator.** The emulator reaches the host's loopback interface at `10.0.2.2`. The app must still connect **by name**, so that SNI and hostname verification are tested (Ch 5). In the debug build, give OkHttp a `Dns` implementation that maps `*.murmur.test` to `10.0.2.2` and passes every other name to `Dns.SYSTEM`. Alternatively, use `adb reverse tcp:8443 tcp:8443`, which lets the device reach the host's port on its own `localhost`, and keep the name mapping. Don't connect to `https://10.0.2.2:…` directly: that tests IP-address matching and fails for the wrong reason.

**iOS Simulator.** The simulator shares the Mac's network stack, so add the names to the Mac's `/etc/hosts`:

```text
127.0.0.1  auth.murmur.test api.murmur.test relay.murmur.test
```

**Physical devices.** Put the lab server on a separate Wi-Fi network, or use a local DNS server that resolves `*.murmur.test` to the lab machine. Real devices are where the release-build checks matter most: confirm that a **release** build refuses the development stack (Ch 26 lab step 5).

**Ports used in the book.** The compose stack publishes `auth` on 8443 and `api` on 8444 (Listing 26.3). The Go lab servers print their ports to a `ready.json` file in their output directory, and the lab scripts read it from there.

## E.9 Supporting tools

| Tool | Use in the book | Setup notes |
|---|---|---|
| **Wireshark** | Watching handshakes (Ch 6–8) | Set `SSLKEYLOGFILE` for one run. In Go use `tls.Config.KeyLogWriter`, in Python `SSLContext.keylog_filename`. Point Wireshark's TLS protocol preferences at the file |
| **An intercepting proxy** (mitmproxy, Burp) | Pinning and MITM labs (Ch 1, 8, 31) | Install its CA only in a test simulator or emulator. Chapter 31's Python proxy (Listing 31.5) needs nothing else |
| **Docker / Compose** | The full local stack (Listing 26.3) | Optional. Every lab in the book also runs without containers, from the Go binaries |
| **An authorization server** | Ch 10–15 | The book's own `murmur-auth` (Ch 27). For comparison, a mainstream open-source authorization server is useful in Ch 10–13. Turn on PKCE enforcement and DPoP where it supports them |
| **Frida** | Hooking labs (Ch 25 §25.6) | Only on dedicated test devices you own |
| **ProVerif** | Formal model (Ch 25) | Install from the official distribution, and run the `.pv` files from the chapter |
| **`govulncheck`, `cargo audit`/`vet`, OSV-Scanner** | Supply chain (Ch 31) | Run in CI. Record the versions with the results |

## E.10 Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `certificate verify failed: Missing Authority Key Identifier` (Python 3.13+) | Test certificates without AKI/SKI fail the stricter default checks | Add SKI/AKI and key-usage extensions (Ch 31 Listing 31.5), rather than relaxing verification |
| Hostname mismatch on the emulator | Connecting to `10.0.2.2` by IP | Map the name with a debug `Dns` (E.8) |
| A pipe or test hangs after `| tail` or `| head` | A child server process still holds the pipe | Send the child's stderr to a file or `/dev/null`, and kill it on exit (`atexit`) |
| `ImportError` on `mlkem` or `mldsa` | `cryptography` built without a PQ-capable backend | Use the PyPI wheel (E.3) |
| The Go build fetches modules and fails | A blocked module proxy | The book's code uses only the standard library. Check for a stray import |
| The release binary still contains lab symbols | A lab file missing `//go:build lab` | Run the release gate (Listing 31.3) |
| UniFFI checksum mismatch at runtime | The bindings were generated from a different build than the library | Regenerate with `--library` from the exact library you ship |
| The NSE is killed with `0xdead10cc` | The database was still locked when the extension was suspended | Close it before calling the content handler (Ch 29) |


---

## E.11 How the listings were verified

Each chapter's "About the listings" note gives only what is particular to that chapter. Everything else follows these conventions:

- **Python and Go listings, and the labs, were run as printed, and the output shown is theirs.** Keys, nonces, device IDs, ports and timings are random or machine-dependent, so they change between runs; test vectors use fixed inputs and do not.
- **Rust crates** were built and tested with the versions in E.2.
- **Kotlin listings** were compiled against the Android SDK, and **Swift listings** type-checked against the iOS SDK, with the versions in E.2. Check them against current SDK documentation.
- **Program output** is reproduced exactly. Where a line is too long for the page, it is broken and the continuation starts with `↪`; join the pieces to get the line the program printed.
- **`scripts/check.sh`** in the companion repository reruns every listing that needs no phone. `VERIFICATION.md` there keeps the full per-chapter notes on what ran, against which versions, and what the labs stand in for.
