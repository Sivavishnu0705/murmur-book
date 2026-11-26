# Listing index

Every code listing in the book, and where it lives in this repository.

| Vol | Listing | Title | File(s) |
|---|---|---|---|
| 1 | 1.1 | Kotlin: a `TrustManager` that accepts every certificate | `ch1code/murmur-android/app/src/main/java/example/insecure/TrustEverything.kt` |
| 1 | 1.2 | Swift: a `URLSessionDelegate` that always trusts | `ch1code/murmur-ios/Murmur/Insecure/TrustEverythingDelegate.swift` |
| 1 | 2.1 | Python: HKDF derivation with labels | `ch2code/listing-2.1.py` |
| 1 | 2.2 | Python: AES-GCM encrypt/decrypt with associated data | `ch2code/listing-2.2.py` |
| 1 | 2.3 | Kotlin: Tink AEAD with a Keystore-protected keyset | `ch2code/android/LocalSecrets.kt` |
| 1 | 2.4 | Python: X25519 exchange | `ch2code/listing-2.4.py` |
| 1 | 2.5 | Swift (CryptoKit): X25519 key agreement + HKDF + ChaChaPoly | `ch2code/ios/listing-2.5.swift` |
| 1 | 2.6 | Python: recovering an ECDSA private key from a repeated nonce | `ch2code/listing-2.6.py` |
| 1 | 2.7 | Python: Ed25519 sign and verify with a context string | `ch2code/listing-2.7.py` |
| 1 | 2.8 | Kotlin: Keystore-backed P-256 key generation | `ch2code/android/DeviceKeys.kt` |
| 1 | 2.9 | Python: GCM nonce reuse leaking the XOR of plaintexts | `ch2code/listing-2.9.py` |
| 1 | 2.10 | Python: the envelope, with a deterministic test vector | `ch2code/envelope.py` |
| 1 | 2.11 | Swift (CryptoKit): the envelope | `ch2code/ios/listing-2.11.swift`<br>`ch2code/ios/listing-2.11.part2.swift` |
| 1 | 2.12 | Kotlin: the envelope (Tink primitives + platform ChaCha20-Poly1305) | `ch2code/android/MurmurEnvelope.kt`<br>`ch2code/android/listing-2.12.kt` |
| 1 | 2.13 | Python: the cached-ephemeral bug | `ch2code/listing-2.13.py` |
| 1 | 3.1 | YAML: threat-model template for Murmur | `ch3code/murmur-threat-model.yaml` |
| 1 | 3.2 | Python: validating the model and printing a ranked checklist | `ch3code/check_threat_model.py` |
| 1 | 4.2 | Go: create a root CA, intermediates, and leaf certificates with correct extensions | `ch4code/murmurpki/listing-4.2.go` |
| 1 | 4.3 | Python: parse a certificate and print SANs, EKUs, and SCTs | `ch4code/inspect_cert.py` |
| 1 | 5.1 | Android Network Security Config: opting in to CT | `ch5code/res/xml/network_security_config.xml` |
| 1 | 5.2 | Go: adding checks on top of standard validation (right) vs. replacing it (wrong) | `ch5code/lab/listing-5.2.go` |
| 1 | 5.3 | Kotlin: hostname verification done right, and two insecure overrides | `ch5code/android/HostnameVerification.kt` |
| 1 | 5.4 | Swift: `SecTrustEvaluateWithError` with added policy checks | `ch5code/ios/listing-5.4.swift` |
| 1 | 5.5 | Python: generate a suite of bad certificates | `ch5code/gen_bad_certs.py` |
| 1 | 5.6 | Go: test server and probe harness | `ch5code/lab/listing-5.6.go` |
| 1 | 5.7 | Python: probe the same cases with Python's `ssl` module | `ch5code/probe_python.py` |
| 1 | — | (unnumbered: network_security_config.xml) | `ch5code/app/src/debug/res/xml/network_security_config.xml` |
| 1 | 6.1 | Python: the TLS 1.3 key schedule, checked against RFC 8448 | `ch6code/tls13_key_schedule.py` |
| 1 | 6.2 | Go: a TLS 1.3-only server with explicit configuration and a key log for lab use | `ch6code/server/listing-6.2.go` |
| 1 | 6.3 | Kotlin (OkHttp) and Swift (URLSession, Network.framework): enforcing a TLS 1.3 minimum | `ch6code/android/MurmurHttp.kt`<br>`ch6code/ios/listing-6.3.swift`<br>`ch6code/ios/listing-6.3.part2.swift`<br>`ch6code/android/listing-6.3.xml` |
| 1 | 6.4 | Python: decrypt and verify a captured handshake from a key log | `ch6code/dissect_tls13.py` |
| 1 | 6.5 | Go: recording proxy and lab client | `ch6code/recproxy/listing-6.5.go`<br>`ch6code/client/listing-6.5-part2.go`<br>`ch6code/client/listing-6.5-part3.go` |
| 1 | 7.1 | Go: session tickets with rotating ticket keys | `ch7code/lab/listing-7.1.go` |
| 1 | 7.2 | Go: RFC 8470 "425 Too Early" and idempotency keys | `ch7code/lab/listing-7.2.go` |
| 1 | 7.3 | Kotlin and Swift: HTTP/3 enablement notes and checking the negotiated protocol | `ch7code/android/listing-7.3.kt`<br>`ch7code/ios/listing-7.3.swift` |
| 1 | 7.4 | Python: HPKE single-shot encryption, base mode, classical and post-quantum | `ch7code/listing-7.4.py` |
| 1 | 7.5 | Go: exporting keying material from a TLS connection | `ch7code/lab/listing-7.5.go` |
| 1 | 7.6 | Python: replaying a recorded client flight | `ch7code/replay.py` |
| 1 | 7.7 | Go: demo driver for resumption, Too Early, and exporters | `ch7code/lab/listing-7.7.go` |
| 1 | 8.1 | Android `network_security_config.xml`: Murmur's baseline with pin-set and backup pins | `ch8code/app/src/main/res/xml/network_security_config.xml`<br>`ch8code/app/src/debug/res/xml/network_security_config.xml` |
| 1 | 8.2 | Kotlin: OkHttp `CertificatePinner` | `ch8code/android/MurmurPinning.kt` |
| 1 | 8.3 | iOS `Info.plist`: ATS baseline and `NSPinnedDomains` | `ch8code/android/listing-8.3.xml` |
| 1 | 8.4 | Bash and Python: compute the SPKI SHA-256 pin from a certificate | `ch8code/spki_pin.sh`<br>`ch8code/spki_pin.py` |
| 1 | 8.5 | Swift: SPKI pin check inside `URLSessionDelegate`, layered on default evaluation | `ch8code/ios/listing-8.5.swift` |
| 1 | 8.6 | Go: SPKI pinning layered on standard validation, with expiry and reporting | `ch8code/lab/listing-8.6.go` |
| 1 | 8.7 | Go: lab driver | `ch8code/lab/listing-8.7.go` |
| 1 | 9.1 | Go: mTLS server requiring and verifying client certificates, extracting the SPIFFE-style URI SAN | `ch9code/lab/listing-9.1.go` |
| 1 | 9.2 | Kotlin: Keystore key generation with attestation challenge; CSR; OkHttp with a custom `X509KeyManager` | `ch9code/android/DeviceMtls.kt` |
| 1 | 9.3 | Swift: Secure Enclave key, App Attest key generation and attestation request, `URLCredential` with `SecIdentity` | `ch9code/ios/listing-9.3.swift` |
| 1 | 9.4 | Go: verifying an Android key attestation chain and an App Attest object (key checks) | `ch9code/lab/listing-9.4.go`<br>`ch9code/lab/listing-9.4-part2.go` |
| 1 | 9.5 | Go: attestation-backed enrollment issuing a short-lived device certificate | `ch9code/lab/listing-9.5.go` |
| 1 | 9.6 | Go: lab driver with simulated Android and iOS attestation | `ch9code/lab/listing-9.6.go` |
| 1 | 10.1 | Raw HTTP of each step of the code flow (annotated) | `ch10code/listing-10.1.http` |
| 1 | 10.2 | Go: resource server JWT validation middleware (issuer, audience, expiry, alg allowlist, JWKS cache) | `ch10code/lab/listing-10.2.go` |
| 1 | 10.3 | Python: decode and inspect a JWT; demonstrate rejecting `alg: none` | `ch10code/listing-10.3.py` |
| 1 | 10.4 | Go: test driver with a mock authorization server | `ch10code/lab/listing-10.4.go` |
| 1 | 10.5 | Go: running the resource server against a real authorization server | `ch10code/lab/listing-10.5.go`<br>`ch10code/listing-10.5.sh` |
| 1 | 11.1 | Go: PKCE verification at the token endpoint, with single-use codes and refresh rotation | `ch11code/lab/token.go` |
| 1 | 11.2 | Kotlin: PKCE verifier/challenge generation; AppAuth flow with Custom Tabs and an App Link redirect | `ch11code/android/MurmurLogin.kt`<br>`ch11code/android/AndroidManifest.xml` |
| 1 | 11.3 | Swift: `ASWebAuthenticationSession` flow with PKCE and a Universal Link callback | `ch11code/ios/listing-11.3.swift` |
| 1 | 11.4 | Kotlin and Swift: a thread-safe token refresh coordinator (single-flight) | `ch11code/android/TokenRefresher.kt`<br>`ch11code/ios/TokenRefresher.swift` |
| 1 | 11.5 | Go: lab driver for code interception and refresh races | `ch11code/lab/main.go` |
| 1 | 12.1 | Go: ID token verification for a backend receiving tokens from the mobile app | `ch12code/lab/idtoken.go` |
| 1 | 12.2 | Go: account-linking logic that requires verified email and existing-session confirmation | `ch12code/lab/linking.go` |
| 1 | 12.3 | Kotlin and Swift: obtaining an ID token with a nonce and sending it to the backend | `ch12code/android/GoogleSignIn.kt`<br>`ch12code/ios/AppleSignIn.swift` |
| 1 | 12.4 | Go: lab driver for ID token verification, step-up and account linking | `ch12code/lab/main.go` |
| 1 | 13.1 | Kotlin: DPoP proof generation with a Keystore P-256 key, OkHttp interceptor | `ch13code/android/DPoP.kt` |
| 1 | 13.2 | Swift: DPoP proof with a Secure Enclave key, URLSession wrapper | `ch13code/ios/listing-13.2.swift` |
| 1 | 13.3 | Go: DPoP verification middleware (signature, `htm`/`htu`, `iat` window, `jti` replay cache, `ath`, `cnf.jkt` match) | `ch13code/lab/dpop.go` |
| 1 | 13.4 | Go: refresh token rotation with family revocation | `ch13code/lab/refresh.go` |
| 1 | 13.5 | Go: lab driver for stolen-token and stolen-proof attacks | `ch13code/lab/main.go` |
| 1 | 14.1 | Kotlin: Credential Manager create/get passkey | `ch14code/android/Passkeys.kt` |
| 1 | 14.2 | Swift: passkey registration and assertion | `ch14code/ios/listing-14.2.swift` |
| 1 | 14.3 | Go: WebAuthn verification using a maintained library (annotated) | `ch14code/lab/passkeys.go` |
| 1 | 14.4 | Go: the same checks with the standard library | `ch14code/lab/verify.go` |
| 1 | 14.5 | Go: lab driver for passkey registration, sign-in and phishing attempts | `ch14code/lab/main.go` |
| 1 | 15.1 | Kotlin/Swift: handling forced logout via push and 401 responses | `ch15code/android/SessionGuard.kt`<br>`ch15code/ios/SessionGuard.swift` |
| 1 | 15.2 | Go: device registry and session list API; revoke-device endpoint | `ch15code/lab/registry.go` |
| 1 | 15.3 | Go: refresh endpoint with attestation re-check and DPoP binding | `ch15code/lab/refresh.go` |
| 1 | 15.4 | Go: lab driver for device-scoped sessions, step-up and remote sign-out | `ch15code/lab/main.go` |
| 2 | 16.1 | Python: toy signed-DH, the misbinding attack, then the SIGMA fix | `ch16code/ake.py`<br>`ch16code/signed_dh.py` |
| 2 | 16.2 | Python: triple-DH key derivation | `ch16code/triple_dh.py` |
| 2 | 16.3 | Python: five toy protocols with their attacks and fixes | `ch16code/toys.py` |
| 2 | 16.4 | Python: lab driver | `ch16code/lab.py` |
| 2 | 17.1 | Python: the Noise XX state machine from the specification | `ch17code/noise_min.py` |
| 2 | 17.2 | Python: Noise XX with a maintained library; transport messages | `ch17code/xx_lib.py` |
| 2 | 17.3 | Rust core with Kotlin/Swift bindings: library-based Noise handshake for device pairing | `ch17code/murmur-core/src/pairing.rs`<br>`ch17code/android/listing-17.3.kt`<br>`ch17code/ios/listing-17.3.swift` |
| 2 | 17.4 | Python: QR-initiated pairing with Noise XXpsk3, SAS and attacks | `ch17code/pairing.py` |
| 2 | 18.1 | Python: XEdDSA (pure Python, educational) | `ch18code/xeddsa.py` |
| 2 | 18.2 | Python: complete X3DH reference implementation with test vectors | `ch18code/x3dh.py` |
| 2 | 18.3 | Go: prekey directory service (publish bundle, fetch-and-consume OPK atomically, rate limits) | `ch18code/server/directory.go` |
| 2 | 18.4 | Python: PQXDH variant using an ML-KEM implementation | `ch18code/pqxdh.py` |
| 2 | 18.5 | Kotlin and Swift: client-side X3DH initiator matching the Python test vectors | `ch18code/android/X3dhInitiator.kt`<br>`ch18code/ios/X3DH.swift` |
| 2 | 18.6 | Go: test-vector check and prekey directory tests | `ch18code/server/main.go` |
| 2 | 18.7 | Python: lab driver | `ch18code/lab.py` |
| 2 | 19.1 | Python: complete Double Ratchet with header, skipped keys, max-skip; test vectors | `ch19code/ratchet.py` |
| 2 | 19.2 | Python test: randomized out-of-order delivery fuzz test | `ch19code/fuzz.py` |
| 2 | 19.3 | Kotlin: ratchet state class + Room/SQLCipher persistence with transactional update | `ch19code/android/RatchetStore.kt` |
| 2 | 19.4 | Swift: ratchet implementation using CryptoKit; GRDB/SQLCipher persistence in the App Group container with IMMEDIATE transactions | `ch19code/ios/Ratchet.swift` |
| 2 | 19.5 | Python: lab driver | `ch19code/lab.py` |
| 2 | 20.1 | Go: device list service with signed device-list records | `ch20code/server/devlist.go` |
| 2 | 20.2 | Python: safety number computation | `ch20code/safety.py` |
| 2 | 20.3 | Kotlin/Swift: QR verification screen logic and key-change warning state machine | `ch20code/android/Verification.kt`<br>`ch20code/ios/Verification.swift` |
| 2 | 20.4 | Python: a minimal key-transparency log (concept) | `ch20code/kt.py` |
| 2 | 20.5 | Go: lab driver for the ghost device attack and signed device lists | `ch20code/server/main.go` |
| 2 | 21.1 | Go: relay accepting sealed envelopes with delivery-token checks | `ch21code/server/relay.go`<br>`ch21code/server/sealed.go` |
| 2 | 21.2 | Swift: Notification Service Extension decrypting a Murmur message | `ch21code/ios/NotificationService.swift` |
| 2 | 21.3 | Kotlin: FCM data-message handler that fetches and decrypts | `ch21code/android/MurmurPushService.kt` |
| 2 | 21.4 | Python: attachment encryption, both designs, with streaming decrypts that verify before release | `ch21code/attach/attachments.py` |
| 2 | 21.5 | Go: lab driver | `ch21code/server/main.go` |
| 2 | 22.1 | Python: sender keys implementation with signing | `ch22code/senderkeys.py` |
| 2 | 22.2 | Go: group membership service with admin-signed state | `ch22code/server/groups.go` |
| 2 | 22.3 | Go: lab driver for admin-signed group membership | `ch22code/server/main.go` |
| 2 | 22.4 | Python: lab driver | `ch22code/lab.py` |
| 2 | 23.1 | Rust: OpenMLS group creation, add member, commit, application message | `ch23code/mls_lab/src/main.rs` |
| 2 | 23.2 | Go: delivery service handling commit ordering and KeyPackage directory | `ch23code/server/ds.go` |
| 2 | 23.3 | Go: lab driver for the delivery service | `ch23code/server/main.go` |
| 2 | 23.4 | UniFFI interface (proc-macro) for Murmur's MLS wrapper | `ch23code/ffi/src/lib.rs` |
| 2 | 23.5 | Kotlin and Swift: calling the MLS wrapper | `ch23code/android/listing-23.5.kt`<br>`ch23code/ios/listing-23.5.swift` |
| 2 | 24.1 | Go: account-authenticated identity key upload binding identity key, device ID, and session via signatures | `ch24code/server/upload.go`<br>`ch24code/server/xeddsa_sign.go` |
| 2 | 24.2 | Go: context strings and domain separation registry for all Murmur KDF labels and signatures | `ch24code/server/contexts.go` |
| 2 | 24.3 | Go: lab driver for the identity-key upload | `ch24code/server/main.go` |
| 2 | 25.1 | Python: Hypothesis-based ratchet state-machine test | `ch25code/test_ratchet_props.py` |
| 2 | 25.2 | Go fuzz test for the Murmur envelope parser | `ch25code/envelope/envelope.go`<br>`ch25code/envelope/envelope_fuzz_test.go` |
| 2 | 25.4 | Python: executable cross-check of the same flaw | `ch25code/check_spk_flaw.py` |
| 2 | 25.5 | Go: measuring a timing side channel | `ch25code/ct/ct_test.go` |
| 2 | 25.6 | CI pipeline YAML running vectors, fuzzers, and lint for insecure APIs | `ch25code/listing-25.6.yaml`<br>`ch25code/lint_insecure.py` |
| 2 | — | (unnumbered: buggy_ratchet.py) | `ch25code/buggy_ratchet.py` |
| 2 | 25.7 | Python: lab driver | `ch25code/find_bug.py` |
| 2 | 26.1 | `murmur.proto` envelope and API definitions | `ch26code/spec/murmur.proto` |
| 2 | 26.2 | Rust: the UniFFI interface | `ch26code/core/src/lib.rs` |
| 2 | 26.3 | `docker-compose.yml` for the local stack | `ch26code/listing-26.3.yaml` |
| 2 | — | (unnumbered: devpki.go) | `ch26code/server/devpki.go` |
| 2 | 26.4 | Go: boot the stack and probe it | `ch26code/server/main.go` |
| 2 | 27.1 | Go: murmur-auth's upstream OIDC configuration | `ch27code/server/oidc.go` |
| 2 | 27.2 | Go: access token, DPoP, device and step-up checks | `ch27code/server/auth.go` |
| 2 | 27.3 | Go: device registry, enrollment with attestation, revocation | `ch27code/server/registry.go` |
| 2 | 27.4 | Go: key directory handlers | `ch27code/server/directory.go` |
| 2 | 27.5 | Go and SQL: transactional storage for the directory, the relay and the DS | `ch27code/server/sql/schema.sql`<br>`ch27code/server/sql/queries.sql`<br>`ch27code/server/pgstore.go` |
| 2 | 27.6 | Python: the SQL under concurrency, on PostgreSQL 16 | `ch27code/pgtest/pg_concurrency.py` |
| 2 | 27.7 | Go: relay queue with ack-based deletion | `ch27code/server/relay.go` |
| 2 | 27.8 | Go: MLS commit ordering logic | `ch27code/server/mls.go` |
| 2 | 27.9 | Go: signed, size-exact upload URLs and retention | `ch27code/server/attach.go` |
| 2 | 27.10 | Go: push gateway client for APNs and FCM | `ch27code/server/push.go` |
| 2 | 27.11 | Go: mTLS service client and server configuration | `ch27code/server/mtls.go` |
| 2 | 27.12 | Go: data-minimizing request logs | `ch27code/server/logging.go` |
| 2 | 27.13 | Python: scripted client | `ch27code/lab/murmur_client.py` |
| 2 | 27.14 | Python: lab driver | `ch27code/lab/lab.py` |
| 2 | 28.1 | Kotlin: DPoP key, key attestation, Play Integrity and proof of possession | `ch28code/android/DeviceEnrollment.kt` |
| 2 | 28.2 | Swift: Secure Enclave DPoP key, App Attest and proof of possession | `ch28code/ios/DeviceEnrollment.swift` |
| 2 | 28.1 | (test) — Python: a port of `derToRaw` against real and malformed signatures | `ch28code/client/der_to_raw_test.py` |
| 2 | 28.3 | Rust: identity key creation with a platform wrap callback | `ch28code/core/src/lib.rs` |
| 2 | 28.4 | Kotlin: `PlatformKeyWrap` on the Android Keystore | `ch28code/android/KeystoreKeyWrap.kt` |
| 2 | 28.5 | Swift: `PlatformKeyWrap` on the Secure Enclave | `ch28code/ios/SecureEnclaveKeyWrap.swift` |
| 2 | 28.6 | Kotlin: Keystore-wrapped SQLCipher passphrase and Room setup | `ch28code/android/MurmurStorage.kt`<br>`ch28code/android/listing-28.6.xml` |
| 2 | 28.7 | Swift: Keychain key, GRDB `DatabasePool` on SQLCipher, file protection | `ch28code/ios/MurmurStorage.swift` |
| 2 | 28.8 | Python: the storage stack as an executable model on SQLCipher 4 | `ch28code/client/device_store.py` |
| 2 | 28.9 | Kotlin: WorkManager prekey job | `ch28code/android/PrekeyWorker.kt` |
| 2 | 28.10 | Swift: BGTaskScheduler prekey job | `ch28code/ios/PrekeyTask.swift` |
| 2 | 28.11 | Python: the client key lifecycle (generation, upload, maintenance, retries) | `ch28code/client/stored_device.py` |
| 2 | 28.12 | Kotlin: DPoP-enabled API client | `ch28code/android/MurmurApiClient.kt` |
| 2 | 28.13 | Swift: DPoP-enabled API client | `ch28code/ios/MurmurAPIClient.swift` |
| 2 | 28.14 | Go: idempotency keys on the server | `ch28code/server/idempotency.go` |
| 2 | 28.15 | Python: lab driver | `ch28code/client/lab.py` |
| 2 | 29.1 | Go: sender certificates (server addition) | `ch29code/server/sendercert.go` |
| 2 | 29.2 | Python: the send and receive pipelines (executable model) | `ch29code/client/messenger.py`<br>`ch29code/core/src/listing-29.2.rs` |
| 2 | 29.3 | Kotlin: send and receive pipelines | `ch29code/android/MessagePipeline.kt` |
| 2 | 29.4 | Swift: send and receive pipelines | `ch29code/ios/MessagePipeline.swift` |
| 2 | 29.5 | Kotlin: streaming attachment encryptor/decryptor with fixed buffers | `ch29code/android/AttachmentCrypto.kt` |
| 2 | 29.6 | Swift: streaming attachment encryptor/decryptor with CryptoKit | `ch29code/ios/AttachmentCrypto.swift` |
| 2 | 29.7 | Python: attachment send and receive (executable model) | `ch29code/client/attach_client.py` |
| 2 | 29.8 | Go: the attachment store with resumable uploads (server addition) | `ch29code/server/attach.go` |
| 2 | 29.9 | Swift: Notification Service Extension | `ch29code/ios/NotificationService.swift` |
| 2 | 29.10 | Kotlin: FCM data-message handler and expedited receive job | `ch29code/android/MurmurMessagingService.kt` |
| 2 | 29.11 | Python: a second process on the same database (the race in lab step 6) | `ch29code/client/nse.py` |
| 2 | 29.12 | Kotlin and Swift: safety number UI logic | `ch29code/android/SafetyNumberViewModel.kt` |
| 2 | 29.13 | Python: lab driver | `ch29code/client/lab.py` |
| 2 | 30.1 | Rust: Murmur MLS wrapper API | `ch30code/core/src/lib.rs` |
| 2 | 30.2 | Python: the group service layer (executable model, driving the real core) | `ch30code/client/group_service.py` |
| 2 | 30.3 | Kotlin and Swift: group service layer | `ch30code/android/GroupService.kt`<br>`ch30code/ios/GroupService.swift` |
| 2 | 30.4 | Go: the KeyPackage directory | `ch30code/server/keypackages.go` |
| 2 | 30.5 | Go: DS endpoints used by groups | `ch30code/server/mls.go` |
| 2 | 30.6 | Rust: MLS cost by group size | `ch30code/core/src/perf.rs` |
| 2 | 30.7 | Python: lab driver | `ch30code/client/lab.py` |
| 2 | 31.1 | Go: key rotation job for token signing keys, with JWKS overlap | `ch31code/server/rotation.go`<br>`ch31code/server/main.go` |
| 2 | 31.2 | Markdown: release checklist | `ch31code/listing-31.2.md` |
| 2 | 31.3 | Python: the release gate | `ch31code/release_gate.py` |
| 2 | 31.4 | Go: the lab's malicious-server mode | `ch31code/server/evil.go` |
| 2 | 31.5 | Python: an intercepting TLS proxy | `ch31code/redteam/mitm_proxy.py` |
| 2 | 31.6 | Python: the red-team driver | `ch31code/redteam/redteam.py` |
| 2 | 31.7 | Python: the fix for RT-4 | `ch31code/redteam/hardened.py` |
| 2 | 31.8 | Swift: the fix for RT-6 | `ch31code/listing-31.8.diff` |
| 2 | 32.1 | Python: Murmur's cryptographic inventory and post-quantum priority list | `ch32code/pq_inventory.py` |
| 2 | 32.2 | Go: what hybrid key exchange costs a TLS 1.3 handshake | `ch32code/server/main.go` |
| 2 | 32.3 | Python: what post-quantum signatures do to Murmur's messages and certificates | `ch32code/pq_sizes.py` |
| 2 | 32.4 | Markdown: protocol evaluation checklist | `ch32code/listing-32.4.md` |
| 2 | — | (unnumbered: gen_vectors.py) | `appendix-c/gen_vectors.py` |
