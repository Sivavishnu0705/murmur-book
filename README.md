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
./scripts/check.sh            # about two minutes
```

Then run any chapter's code from its folder, for example:

```bash
cd ch19code && python3 lab.py           # Double Ratchet lab
cd ch6code  && python3 tls13_key_schedule.py   # checked against RFC 8448
cd ch7code/lab && go run .              # TLS resumption, Too Early, exporters
```

Versions, the local PKI, PostgreSQL, and emulator and simulator setup are covered in Appendix E.

## What CI checks

On every push, `scripts/check.sh` checks the following:

- **45 Python listings and labs** run and finish without errors, including every Part IV protocol (AKE, Noise, X3DH, PQXDH, Double Ratchet, safety numbers, key transparency, sender keys) and the Chapter 25 fuzzers and property tests.
- **Appendix C** regenerates every test vector, and its output must be **identical, byte for byte,** to the output printed in the book.
- **24 Go programs** build and pass `go vet`.
- The three protobuf schemas compile.

Kotlin, Swift, and Rust aren't built in CI. The book's Appendix E.2 says how each was checked.

## Known gaps

The book describes some supporting code without printing it, so that code isn't in this repository yet:

| Folder | What's missing | Why |
|---|---|---|
| `ch27code/server` … `ch30code/server` | `main.go` (routing and wiring), `store.go` (in-memory store), shared types and helpers | Chapter 27 lists them under "Described only" |
| `ch14code/lab` | `cborEncode` helper | Not printed |
| `ch14code/library` | murmur-auth's `Account`, `AccountDB` and `ErrConfirmFromAnotherDevice` types | Listing 14.3 uses them but doesn't print them |
| Rust crates (`core/`, `ch23code/`) | `Cargo.toml` files | Not printed |
| Chapters 27–31 labs | Need the running server above | — |

Until those files are added, the Chapter 27–31 labs can't run from this repository.

Some files are assembled rather than copied, and each one says so in its header:
- `ch27code/spec/murmur.proto` and `ch29code/spec/murmur.proto` are Listing 26.1 plus the spec changes printed in Chapters 27 and 29.
- `ch24code/server/directory_ch18.go` is Listing 18.3, which Chapter 24 reuses unchanged.
- `appendix-c/pqxdh_vector.json` holds the ML-KEM ciphertext printed in full in Appendix C.

## Safety

Many listings are **deliberately insecure**. They're marked ⚠️ INSECURE in the code and in the book, and exist to be attacked. The toy protocols in Chapter 16 and the Chapter 31 malicious-server mode (`-tags lab`) are teaching tools. Never deploy them, and never put the lab PKI or test keys near real accounts.

## Reporting errors

Found a bug in a listing, or a difference between the book and this code? Open an issue with the listing number. Corrections go here first, so this repository can be more current than your printed copy.
