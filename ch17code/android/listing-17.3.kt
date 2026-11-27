// Android: the platform layer only moves bytes and shows UI.
val pairing = Pairing.initiator(staticKey = keyStore.pairingStaticKey(),
    qr = QrPayload.parse(scanned))
relay.send(pairing.write(ByteArray(0)))                 // -> e
// <- e, ee, s, es (+ its DPoP jkt)
val newDeviceInfo = pairing.read(relay.receive())
// throws on fingerprint mismatch
pairing.verifyPeer()
// "Does the other screen show 114 478?"
showCode(pairing.sas())
// -> s, se, psk
if (userConfirmed()) relay.send(pairing.write(enrollmentGrant(newDeviceInfo)))
