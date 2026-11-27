# Murmur: companion code

Companion code for the two-volume book *Volume 1: Trust, Transport, and Identity* and *Volume 2: End-to-End Encryption and the Build*.

Every listing in both volumes is here, organized by chapter. Where the book prints only an excerpt, this repository has the complete file. The book points to each file by its path, for example:

> **Listing 27.7: Go: the relay.** Full file: `ch27code/server/relay.go`

The full list of listings and their files is in [LISTINGS.md](LISTINGS.md).

## What you need

**To follow the book you only need to read Python.** The protocol chapters teach and attack every design in Python. The other languages show how Murmur is built for production:

| Language | Used for | Where |
|---|---|---|
| Python | Protocols, attacks, labs, test vectors | Every chapter |
| Go | The Murmur server and the TLS, OAuth, and PKI labs | `chNNcode/server/`, `chNNcode/lab/` |
| Rust | The shared client core (OpenMLS and UniFFI) | `chNNcode/core/` |
| Kotlin | The Android app | `chNNcode/android/` |
| Swift | The iOS app | `chNNcode/ios/` |

Where the book prints only one mobile platform, it prints Kotlin, and the Swift version is here. Both appear in print where Android and iOS differ in a way that matters for security, such as Keystore and the Secure Enclave, or Network Security Config and ATS.

## Layout

```text
ch2code/ … ch32code/     one folder per chapter
  *.py                   Python listings and labs (run from inside the folder)
  lab/, server/          Go programs; each folder with a go.mod is one program
  android/, ios/         Kotlin and Swift listings
  core/                  Rust core
  spec/                  protobuf schema as of that chapter (Ch 26, 27, 29)
appendix-c/              test-vector generator and its expected output
scripts/check.sh         runs everything that can run without a phone or the full server
LISTINGS.md              listing number → file
```

This is the layout Appendix E describes (`ch27code/`, `ch30code/`, …). The labs' `sys.path` lines expect it, so keep folders where they are.

## Quick start

```bash
python3 -m venv ~/murmur-venv && . ~/murmur-venv/bin/activate
pip install -r requirements.txt
./scripts/check.sh            # about 15 minutes with Rust, 3 without
```

Then run any chapter's code from its folder, for example:

```bash
cd ch19code && python3 lab.py           # Double Ratchet lab
cd ch6code  && python3 tls13_key_schedule.py   # checked against RFC 8448
cd ch7code/lab && go run .              # TLS resumption, Too Early, exporters
```

The Part V labs run against the Go server of their chapter:

```bash
cd ch27code/server && go run . -selftest                  # MLS framing, mTLS, log allowlist
go build -o /tmp/murmur-lab . && cd ../lab && python3 lab.py /tmp/murmur-lab
```

Chapters 30 and 31 also need the Rust core and its Python bindings (Appendix E.6):

```bash
cd ch30code/core && cargo build --release
cargo run --release --bin uniffi-bindgen -- generate \
    --library target/release/libmurmur_groups.so --language python --out-dir py
cp target/release/libmurmur_groups.so py/
```

Versions, the local PKI, PostgreSQL, and emulator and simulator setup are covered in Appendix E.

## The server, chapter by chapter

`ch27code/server` is the complete lab server: the printed listings plus what Chapter 27
lists under "Described only" (`main.go` for routing and wiring, `store.go` for the in-memory
store, the self-test, and the Chapter 13, 18 and 26 code it reuses unchanged).

`ch28code/server` through `ch31code/server` are snapshots: each is the previous chapter's
server plus that chapter's changes, and each builds and runs on its own. The changes are
noted at the top of each changed file. In `ch31code/server`, everything lab-only carries the
`lab` build tag: `go build .` produces a release binary that refuses to start (exit 2), and
`go build -tags lab .` produces the lab server with the malicious-server mode of Listing 31.4.
Listing 31.1, the key-rotation job, is a separate program in `ch31code/rotation`.

`ch27code/mlsgen` regenerates `ch27code/server/mls_vectors.json`, the OpenMLS 0.7.4 messages
that the Chapter 27 self-test and lab send through the delivery service.

## What CI checks

On every push, `scripts/check.sh` checks the following:

- **Every Python listing and lab** runs and finishes without errors, including every Part IV
  protocol (AKE, Noise, X3DH, PQXDH, Double Ratchet, safety numbers, key transparency, sender
  keys) and the Chapter 25 fuzzers and property tests.
- **Appendix C** regenerates every test vector, and its output must be **identical, byte for
  byte,** to the output printed in the book.
- **Every Go program** builds and passes `go vet` (with `-tags lab` where a directory has lab
  code), and the three protobuf schemas compile.
- **The Part V labs run end to end:** the Chapter 14 passkey lab, the Chapter 27 self-test, and
  the Chapter 27, 28 and 29 labs against their servers.
- **Rust:** every crate builds (Chapters 17, 23, 26, 27, 28 and 30). The Chapter 30 core's
  Python bindings drive the Chapter 30 lab and the Chapter 31 red team, and the release gate of
  Listing 31.3 must block the Chapter 30 tree and pass with Chapter 31's fixes.
- The Chapter 31 release build refuses to start, and the rotation demo runs.

Kotlin and Swift aren't built in CI. The book's Appendix E.2 says how they were checked; none
of the platform code has been run on a device.

## Line width

Every printed listing fits in 80 columns, so the book and this repository show the same
lines. Go uses 4-space indentation rather than `gofmt`'s tabs for the same reason; the files
that the book does not print are `gofmt`-formatted.
