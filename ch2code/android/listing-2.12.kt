import com.google.crypto.tink.subtle.X25519
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class EnvelopeVectorTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test fun matchesPythonVector() {
        val r = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val e = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val expected = hex("01de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f" +
                           "edb334937ff8c4094bce55fdb553e8ac164a19e8175802b7c4c44e7b3aa42b000eef")
        val pt = "Are you free at 7?".toByteArray()
        val sealed = MurmurEnvelope.seal(X25519.publicFromPrivate(r), pt, ephemeralPriv = e)
        assertArrayEquals(expected, sealed)
        assertArrayEquals(pt, MurmurEnvelope.open(r, expected))
    }
}
