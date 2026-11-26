// Android: the platform layer only moves bytes and shows UI.
val pairing = Pairing.initiator(staticKey = keyStore.pairingStaticKey(), qr = QrPayload.parse(scanned))
relay.send(pairing.write(ByteArray(0)))                 // -> e
val newDeviceInfo = pairing.read(relay.receive())       // <- e, ee, s, es (+ its DPoP jkt)
pairing.verifyPeer()                                    // throws on fingerprint mismatch
showCode(pairing.sas())                                 // "Does the other screen show 114 478?"
if (userConfirmed()) relay.send(pairing.write(enrollmentGrant(newDeviceInfo)))   // -> s, se, psk
