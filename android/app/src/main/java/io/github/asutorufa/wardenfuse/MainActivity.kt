package io.github.asutorufa.wardenfuse

import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.SystemClock
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.json.JSONObject
import java.net.Socket
import java.util.UUID
import java.util.concurrent.Executors
import javax.net.ssl.SSLException

class MainActivity : AppCompatActivity() {
    private lateinit var content: LinearLayout
    private lateinit var keys: DeviceKeys
    private val network = Executors.newSingleThreadExecutor()
    private val responses = Executors.newSingleThreadExecutor()
    private var active: Session? = null
    private var macName: String? = null
    private var status = ""
    private var notice: String? = null
    private var request: Request? = null
    private var prompt: CancellationSignal? = null
    private var waitingForResult = false
    private var canScan = false
    private var canForget = false

    private val scanner = registerForActivityResult(ScanContract()) { result ->
        val contents = result.contents ?: return@registerForActivityResult
        val offer = runCatching { PairingOffer.parse(contents) }.getOrElse {
            status = getString(R.string.invalid_qr)
            render()
            return@registerForActivityResult
        }
        if (!hasBiometrics()) {
            offer.token.fill(0)
            status = getString(R.string.strong_required)
            render()
            return@registerForActivityResult
        }
        beginPairing(offer)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        keys = DeviceKeys(applicationContext)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
        }
        setContentView(ScrollView(this).apply {
            addView(content)
            ViewCompat.setOnApplyWindowInsetsListener(this) { view, insets ->
                val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
                insets
            }
        })
    }

    override fun onStart() {
        super.onStart()
        connectSaved()
    }

    override fun onStop() {
        stop()
        super.onStop()
    }

    override fun onDestroy() {
        network.shutdown()
        responses.shutdown()
        super.onDestroy()
    }

    private fun connectSaved() {
        val session = start()
        network.execute {
            val profile = try {
                keys.profile()
            } catch (_: Exception) {
                show(session) { status = getString(R.string.local_error); canForget = true }
                return@execute
            }
            if (profile == null) {
                show(session) { status = getString(R.string.get_started); canScan = true }
            } else {
                show(session) { macName = profile.mac.name; canForget = true }
                listenSaved(session, profile)
            }
        }
    }

    private fun beginPairing(offer: PairingOffer) {
        val session = start()
        macName = offer.mac.name
        status = getString(R.string.pairing, offer.mac.name)
        render()
        network.execute {
            var saved = false
            try {
                val modulus = keys.createEnvelopeKey()
                if (session.stopped) return@execute
                val profile = Pairing(offer.mac, UUID.randomUUID())
                val credential = keys.newCredential()
                try {
                    // Save before sending. A lost success reply can be recovered by reconnecting.
                    keys.save(profile, credential)
                    saved = true
                    show(session) { canForget = true }
                    session.connect(profile.mac) { channel ->
                        channel.write(
                            channel.command("pair", profile.id)
                                .put("name", Build.MODEL.filterNot(Char::isISOControl).take(48).ifBlank { "Android" })
                                .put("modulus", modulus),
                        )
                        val proof = offer.token + credential
                        try {
                            channel.write(proof)
                        } finally {
                            proof.fill(0)
                            offer.token.fill(0)
                        }
                        val reply = channel.read()
                        check(reply.getString("status") == "confirm")
                        val code = reply.getString("code")
                        check(code.length == 8 && code.all { it in '0'..'9' })
                        show(session) { status = getString(R.string.confirm, code, profile.mac.name) }
                        channel.timeout(125_000)
                        check(channel.read().getString("status") == "paired")
                    }
                } finally {
                    credential.fill(0)
                }
                if (!session.stopped) listenSaved(session, profile)
            } catch (_: Exception) {
                show(session) {
                    status = getString(if (saved) R.string.pair_failed else R.string.key_unavailable)
                    canScan = !saved
                    canForget = saved
                }
            } finally {
                offer.token.fill(0)
            }
        }
    }

    private fun listenSaved(session: Session, profile: Pairing) {
        val credential = try {
            keys.credential(profile)
        } catch (_: Exception) {
            show(session) { status = getString(R.string.local_error) }
            return
        }
        try {
            while (!session.stopped) {
                try {
                    val again = session.connect(profile.mac) { channel ->
                        channel.write(channel.command("listen", profile.id))
                        channel.write(credential)
                        when (channel.read().getString("status")) {
                            "unpaired" -> {
                                show(session) { status = getString(R.string.unpaired) }
                                return@connect false
                            }
                            "busy" -> {
                                Thread.sleep(250)
                                return@connect true
                            }
                            "ready" -> show(session) { status = getString(R.string.waiting) }
                            else -> error("Invalid Mac reply")
                        }
                        channel.timeout(32_000)
                        val message = channel.read()
                        if (message.getString("status") == "request") {
                            handleRequest(session, profile, channel, message)
                        } else {
                            check(message.getString("status") == "idle")
                        }
                        true
                    }
                    if (!again) return
                } catch (_: SSLException) {
                    show(session) { status = getString(R.string.identity_changed) }
                    return
                } catch (_: Exception) {
                    show(session) { status = getString(R.string.disconnected) }
                    if (!session.stopped) Thread.sleep(1_500)
                }
            }
        } finally {
            credential.fill(0)
        }
    }

    private fun handleRequest(session: Session, profile: Pairing, channel: Channel, message: JSONObject) {
        val remaining = message.getLong("remaining_ms").also { require(it in 0..60_000) }
        val browser = message.getString("browser").take(80)
        val title = getString(
            if (message.getBoolean("verify")) R.string.verify_request else R.string.unlock_request,
            browser,
            profile.mac.name,
        )
        val pending = Request(
            session, channel, title, message.getString("challenge").decodeBytes(SECRET_LENGTH),
            message.getString("wrapped_key").decodeBytes(256), SystemClock.elapsedRealtime() + remaining,
        )
        show(session) {
            request = pending
            notice = null
        }
        var outcome = R.string.interrupted
        try {
            channel.timeout(remaining.toInt() + IO_TIMEOUT)
            outcome = when (channel.read().getString("status")) {
                "approved" -> R.string.approved
                "cancelled" -> R.string.cancelled
                "expired" -> R.string.expired
                else -> R.string.rejected
            }
        } finally {
            val result = outcome
            show(session) {
                if (request === pending) {
                    clearRequest()
                    notice = getString(result)
                }
            }
        }
    }

    private fun approve(pending: Request) {
        if (!isCurrent(pending) || waitingForResult) return
        if (!hasBiometrics()) {
            notice = getString(R.string.strong_required)
            render()
            return
        }
        val cipher = try {
            keys.newUnsealer()
        } catch (_: Exception) {
            notice = getString(R.string.key_unavailable)
            render()
            return
        }
        val cancel = CancellationSignal()
        prompt = cancel
        waitingForResult = true
        render()
        BiometricPrompt.Builder(this)
            .setTitle(getString(R.string.app_name))
            .setSubtitle(pending.title)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButton(getString(R.string.cancel), mainExecutor) { _, _ -> cancelRequest(pending) }
            .build()
            .authenticate(
                BiometricPrompt.CryptoObject(cipher),
                cancel,
                mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (!isCurrent(pending)) return
                        prompt = null
                        responses.execute {
                            val authorized = result.cryptoObject?.cipher
                            if (authorized == null || pending.expired) {
                                send(pending, null)
                            } else {
                                val secret = runCatching { authorized.doFinal(pending.wrappedKey) }.getOrNull()
                                try {
                                    send(pending, secret)
                                } finally {
                                    secret?.fill(0)
                                }
                            }
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (prompt === cancel && isCurrent(pending)) {
                            notice = errString.toString()
                            cancelRequest(pending)
                        }
                    }
                },
            )
    }

    private fun cancelRequest(pending: Request) {
        if (!isCurrent(pending)) return
        val signal = prompt
        prompt = null
        signal?.cancel()
        waitingForResult = true
        responses.execute { send(pending, null) }
        render()
    }

    private fun send(pending: Request, secret: ByteArray?) {
        if (pending.session.stopped) return
        val proof = if (secret?.size == SECRET_LENGTH && !pending.expired) {
            pending.challenge + secret
        } else {
            pending.challenge.copyOf()
        }
        try {
            pending.channel.write(proof)
        } catch (_: Exception) {
            // The reader observes a disconnect or the request deadline.
        } finally {
            proof.fill(0)
        }
    }

    private fun hasBiometrics(): Boolean = getSystemService(BiometricManager::class.java)
        .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    private fun isCurrent(pending: Request) = active === pending.session && request === pending

    private fun show(session: Session, update: () -> Unit) = runOnUiThread {
        if (active === session && !session.stopped) {
            update()
            render()
        }
    }

    private fun start(): Session {
        stop()
        macName = null
        notice = null
        canScan = false
        canForget = false
        status = getString(R.string.connecting)
        render()
        return Session().also { active = it }
    }

    private fun stop() {
        active?.stop()
        active = null
        clearRequest()
    }

    private fun clearRequest() {
        request = null
        val signal = prompt
        prompt = null
        signal?.cancel()
        waitingForResult = false
    }

    private fun forget() {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.forget_title)
            .setMessage(R.string.forget_detail)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.forget) { _, _ ->
                val session = start()
                network.execute {
                    val deleted = runCatching { keys.forget() }.isSuccess
                    show(session) {
                        status = getString(if (deleted) R.string.get_started else R.string.local_error)
                        canScan = deleted
                        canForget = !deleted
                    }
                }
            }
            .show()
    }

    private fun render() {
        content.removeAllViews()
        label(getString(R.string.app_name), com.google.android.material.R.style.TextAppearance_Material3_HeadlineMedium)
        macName?.let { label(getString(R.string.mac, it)) }
        val pending = request
        if (pending != null) {
            label(pending.title, com.google.android.material.R.style.TextAppearance_Material3_TitleLarge)
            if (waitingForResult) label(getString(R.string.authenticating))
            button(R.string.approve) { approve(pending) }.isEnabled = !waitingForResult
            button(R.string.cancel) { cancelRequest(pending) }.isEnabled = !waitingForResult
        } else {
            label(status)
            if (canScan) {
                if (packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)) {
                    button(R.string.scan) {
                        scanner.launch(
                            ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                .setPrompt(getString(R.string.scan_prompt)).setBeepEnabled(false),
                        )
                    }
                } else {
                    label(getString(R.string.camera_required))
                }
            }
            if (canForget) button(R.string.forget, ::forget)
        }
        notice?.let { label(it) }
    }

    private fun label(value: String, appearance: Int = com.google.android.material.R.style.TextAppearance_Material3_BodyLarge) {
        content.addView(TextView(this).apply {
            setTextAppearance(appearance)
            text = value
            setPadding(0, 0, 0, dp(12))
        })
    }

    private fun button(title: Int, action: () -> Unit): View = MaterialButton(this).apply {
        setText(title)
        setOnClickListener { action() }
        content.addView(this)
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private class Request(
        val session: Session,
        val channel: Channel,
        val title: String,
        val challenge: ByteArray,
        val wrappedKey: ByteArray,
        private val deadline: Long,
    ) {
        val expired get() = SystemClock.elapsedRealtime() >= deadline
    }

    private class Session {
        @Volatile
        var stopped = false
            private set
        private var raw: Socket? = null

        @Synchronized
        fun stop() {
            stopped = true
            runCatching { raw?.close() }
        }

        fun <T> connect(mac: Mac, exchange: (Channel) -> T): T {
            val socket = synchronized(this) {
                check(!stopped)
                Socket().also { raw = it }
            }
            try {
                return socket.use { Channel.connect(it, mac).use(exchange) }
            } finally {
                synchronized(this) { raw = null }
            }
        }
    }
}
