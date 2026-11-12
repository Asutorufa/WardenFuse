package io.github.asutorufa.wardenfuse

import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.UUID
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.TrustManagerFactory

private const val VERSION = 1
private const val PORT = 47635
private const val TLS_NAME = "wardenfuse.local"
internal const val SECRET_LENGTH = 32
private const val FRAME_LIMIT = 4096
internal const val IO_TIMEOUT = 5_000

internal fun ByteArray.b64(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(this)

internal fun String.decodeBytes(length: Int): ByteArray =
    Base64.getUrlDecoder().decode(this).also { require(it.size == length) }

internal data class Mac(val name: String, val host: String, val certificate: ByteArray) {
    val address: InetAddress
        get() {
            val parts = host.split('.')
            require(parts.size == 4)
            return InetAddress.getByAddress(parts.map {
                require(it.isNotEmpty() && it.all { c -> c in '0'..'9' })
                it.toInt().also { value -> require(value in 0..255) }.toByte()
            }.toByteArray())
        }

    fun json(): JSONObject = JSONObject().put("name", name).put("host", host).put("certificate", certificate.b64())

    companion object {
        fun from(json: JSONObject): Mac = Mac(
            json.getString("name").also { require(it.isNotBlank() && it.length <= 96) },
            json.getString("host"),
            Base64.getUrlDecoder().decode(json.getString("certificate")).also { require(it.size in 1..1024) },
        ).also {
            require(!it.address.isAnyLocalAddress && !it.address.isLoopbackAddress && !it.address.isMulticastAddress)
        }
    }
}

internal data class PairingOffer(val mac: Mac, val token: ByteArray) {
    companion object {
        fun parse(value: String): PairingOffer {
            require(value.length <= FRAME_LIMIT)
            val json = JSONObject(value)
            require(json.getInt("version") == VERSION && json.getInt("port") == PORT)
            return PairingOffer(Mac.from(json), json.getString("token").decodeBytes(SECRET_LENGTH))
        }
    }
}

internal data class Pairing(val mac: Mac, val id: UUID) {
    fun json(): JSONObject = mac.json().put("id", id.toString())

    companion object {
        fun from(json: JSONObject) = Pairing(Mac.from(json), UUID.fromString(json.getString("id")))
    }
}

internal class Channel(private val socket: SSLSocket) : Closeable {
    private val input = DataInputStream(socket.inputStream)
    private val output = DataOutputStream(socket.outputStream)

    fun command(op: String, id: UUID): JSONObject =
        JSONObject().put("op", op).put("version", VERSION).put("id", id.toString())

    fun write(json: JSONObject) = write(json.toString().toByteArray(Charsets.UTF_8))

    fun write(data: ByteArray) = writeFrame(output, data)

    fun read(): JSONObject = JSONObject(String(readFrame(input), Charsets.UTF_8))

    fun timeout(milliseconds: Int) {
        socket.soTimeout = milliseconds
    }

    override fun close() = socket.close()

    companion object {
        fun connect(raw: Socket, mac: Mac): Channel {
            raw.connect(InetSocketAddress(mac.address, PORT), IO_TIMEOUT)
            raw.soTimeout = IO_TIMEOUT
            val cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(mac.certificate)) as X509Certificate
            cert.checkValidity()
            val anchors = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null)
                setCertificateEntry(TLS_NAME, cert)
            }
            val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(anchors) }
            val tls = SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
            // The socket is already connected to the numeric QR address. This name is used for TLS only.
            val socket = tls.socketFactory.createSocket(raw, TLS_NAME, PORT, true) as SSLSocket
            try {
                socket.enabledProtocols = arrayOf("TLSv1.3")
                socket.sslParameters = socket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                socket.startHandshake()
                val peer = socket.session.peerCertificates.singleOrNull()?.encoded
                if (peer == null || !MessageDigest.isEqual(mac.certificate, peer)) {
                    throw SSLPeerUnverifiedException("Mac certificate mismatch")
                }
                return Channel(socket)
            } catch (error: Exception) {
                raw.close()
                throw error
            }
        }
    }
}

internal fun writeFrame(output: DataOutputStream, data: ByteArray) {
    require(data.size in 1..FRAME_LIMIT)
    output.writeInt(data.size)
    output.write(data)
    output.flush()
}

internal fun readFrame(input: DataInputStream): ByteArray {
    val size = input.readInt()
    require(size in 1..FRAME_LIMIT)
    return ByteArray(size).also(input::readFully)
}
