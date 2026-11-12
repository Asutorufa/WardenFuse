package io.github.asutorufa.wardenfuse

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

private const val KEYSTORE = "AndroidKeyStore"
private const val ENVELOPE_KEY = "wardenfuse.envelope.v1"
private const val CREDENTIAL_KEY = "wardenfuse.credential.v1"
private const val AES_GCM = "AES/GCM/NoPadding"

internal val ENVELOPE_OAEP = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

internal class DeviceKeys(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "pairing.json"))

    private fun keyStore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    fun profile(): Pairing? = try {
        Pairing.from(JSONObject(String(file.readFully(), Charsets.UTF_8)).getJSONObject("mac"))
    } catch (_: java.io.FileNotFoundException) {
        null
    }

    /** Generates a fresh hardware-backed key with no time window for reusing an authentication. */
    fun createEnvelopeKey(): String {
        val pair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE).run {
            initialize(
                KeyGenParameterSpec.Builder(ENVELOPE_KEY, KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(2048)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    .setInvalidatedByBiometricEnrollment(true)
                    .build(),
            )
            generateKeyPair()
        }
        val info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE)
            .getKeySpec(pair.private, KeyInfo::class.java)
        // This accessor also works on Android 11. StrongBox is optional.
        @Suppress("DEPRECATION")
        check(info.isInsideSecureHardware && info.isUserAuthenticationRequirementEnforcedBySecureHardware)
        val key = pair.public as RSAPublicKey
        check(key.modulus.bitLength() == 2048 && key.publicExponent == BigInteger.valueOf(65_537))
        return key.modulus.toByteArray().copyOfRange(1, 257).b64()
    }

    /** The returned Cipher can only decrypt after its own BiometricPrompt CryptoObject succeeds. */
    fun newUnsealer(): Cipher {
        val key = keyStore().getKey(ENVELOPE_KEY, null) as? PrivateKey ?: error("Missing biometric key")
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding").apply {
            init(Cipher.DECRYPT_MODE, key, ENVELOPE_OAEP)
        }
    }

    fun newCredential(): ByteArray = ByteArray(SECRET_LENGTH).also(SecureRandom()::nextBytes)

    fun save(profile: Pairing, credential: ByteArray) {
        val key = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
            init(
                KeyGenParameterSpec.Builder(CREDENTIAL_KEY, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build(),
            )
            generateKey()
        }
        val metadata = profile.json().toString()
        val cipher = Cipher.getInstance(AES_GCM).apply {
            init(Cipher.ENCRYPT_MODE, key)
            updateAAD(metadata.toByteArray(Charsets.UTF_8))
        }
        val json = JSONObject().put("mac", JSONObject(metadata))
            .put("nonce", cipher.iv.b64()).put("credential", cipher.doFinal(credential).b64())
        val stream = file.startWrite()
        try {
            stream.write(json.toString().toByteArray(Charsets.UTF_8))
            file.finishWrite(stream)
        } catch (error: Exception) {
            file.failWrite(stream)
            throw error
        }
    }

    fun credential(profile: Pairing): ByteArray {
        val data = JSONObject(String(file.readFully(), Charsets.UTF_8))
        val key = keyStore().getKey(CREDENTIAL_KEY, null) as? SecretKey ?: error("Missing device credential")
        val cipher = Cipher.getInstance(AES_GCM).apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, data.getString("nonce").decodeBytes(12)))
            updateAAD(profile.json().toString().toByteArray(Charsets.UTF_8))
        }
        return cipher.doFinal(data.getString("credential").decodeBytes(SECRET_LENGTH + 16))
    }

    fun forget() {
        file.delete()
        keyStore().apply {
            deleteEntry(ENVELOPE_KEY)
            deleteEntry(CREDENTIAL_KEY)
        }
    }
}
