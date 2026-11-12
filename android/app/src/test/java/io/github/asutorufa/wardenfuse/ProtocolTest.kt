package io.github.asutorufa.wardenfuse

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.security.KeyPairGenerator
import javax.crypto.Cipher

class ProtocolTest {
    @Test
    fun framingUsesBigEndianLengthAndKeepsProofBytesIntact() {
        val proof = ByteArray(64) { it.toByte() }
        val buffer = ByteArrayOutputStream()
        writeFrame(DataOutputStream(buffer), proof)
        assertArrayEquals(byteArrayOf(0, 0, 0, 64), buffer.toByteArray().copyOfRange(0, 4))
        assertArrayEquals(proof, readFrame(DataInputStream(ByteArrayInputStream(buffer.toByteArray()))))
    }

    @Test
    fun framingRejectsTruncatedAndOversizedReplies() {
        assertThrows(EOFException::class.java) { readFrame(input(0, 0, 0, 2, 1)) }
        assertThrows(IllegalArgumentException::class.java) { readFrame(input(0, 0, 16, 1)) }
        assertThrows(IllegalArgumentException::class.java) { readFrame(input(0, 0, 0, 0)) }
    }

    @Test
    fun envelopeUsesSha256OaepWithAndroidCompatibleMgf() {
        val key = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        val secret = ByteArray(SECRET_LENGTH) { (255 - it).toByte() }
        cipher.init(Cipher.ENCRYPT_MODE, key.public, ENVELOPE_OAEP)
        val ciphertext = cipher.doFinal(secret)
        cipher.init(Cipher.DECRYPT_MODE, key.private, ENVELOPE_OAEP)
        assertArrayEquals(secret, cipher.doFinal(ciphertext))
    }

    private fun input(vararg bytes: Byte) = DataInputStream(ByteArrayInputStream(bytes))
}
