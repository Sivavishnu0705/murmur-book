// iOS: same calls through the generated Swift bindings.
let pairing = try Pairing.initiator(staticKey: keychain.pairingStaticKey(), qr: QrPayload(scanned))
try await relay.send(pairing.write(payload: Data()))
let info = try pairing.read(msg: await relay.receive())
try pairing.verifyPeer()
guard await confirmCode(try pairing.sas()) else { return }
try await relay.send(pairing.write(payload: enrollmentGrant(info)))
