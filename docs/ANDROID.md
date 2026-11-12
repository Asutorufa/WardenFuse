# Android browser unlock

WardenFuse can use a paired Android phone to unlock the official Bitwarden browser extension.
Android is an opt-in browser authentication method. The SSH agent continues to use the macOS
authentication settings.

## Build and install

Use Android 11 or later with a Class 3 biometric and a screen lock configured. The device must
support hardware-backed RSA decryption with per-operation biometric authentication. A camera
is needed for pairing.

Build the Mac app with `scripts/build-app.sh`. For Android, use JDK 17, Android SDK Platform 36
and Build Tools 35.0.0. Open the `android/` project in Android Studio or build and install from a terminal.

```sh
cd android
./gradlew :app:assembleDebug :app:lintDebug :app:testDebugUnitTest
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The Android SDK and Gradle dependencies are downloaded at build time. Pairing and approval use
the local network. Normal Bitwarden sign-in and sync still use the configured Bitwarden server.

## Pair a phone

1. Connect the Mac and phone to the same local network. Sign in to WardenFuse on the Mac and
   set up its native messaging host for your browser under **Settings → Browser**.
2. Select **Android Biometric** under **Browser authentication**, then click
   **Pair Android Device…**. Choose the IPv4 address the phone can reach and show the QR code.
3. Open WardenFuse on Android and scan the code from the Mac's settings window. The QR code is
   valid for two minutes and can be claimed once. Enter the eight-digit code from the phone
   into the Mac's pairing sheet.
4. Confirm with the Mac's existing Touch ID or macOS password policy. The phone appears under
   **Paired Devices**. Each phone app holds one Mac pairing and each Mac can enroll up to eight phones.

## Unlock

Enable **Unlock with biometrics** in the official extension's account security settings. When
Bitwarden asks to unlock, open WardenFuse on the phone, review the Mac and browser shown, then tap
**Authenticate** and complete the system biometric prompt. The same method applies to identity
verification requests from the extension. Each request requires a fresh biometric operation.

The default approval window is 30 seconds and can be changed in the Mac Browser settings. A
phone can cancel the request in the app or by leaving it after it has claimed a request. The Mac
can cancel under **Waiting for Android approval**. A failure returns no user key to the extension.
For recovery, unlock with your Bitwarden master password in the extension or explicitly select
**Touch ID / macOS Password** in WardenFuse.

## Security and recovery

- The QR code contains the Mac's IPv4 address, TLS certificate and a random single-use token.
  The phone trusts only that certificate. TLS 1.3 authenticates the Mac and protects traffic
  against interception and alteration. A random per-device credential authenticates the phone
  within TLS. The Mac stores its SHA-256 hash. The phone seals the credential with a separate
  Android Keystore AES-GCM key in app-private storage excluded from backup.
- Successful Mac authentication releases the existing Keychain user key to Rust for enrollment.
  Rust verifies it against the current synced account key, then encrypts it in a per-device
  ChaCha20-Poly1305 envelope using a random 256-bit key. The account session, account key
  revision and device ID are authenticated with the ciphertext. The Mac stores the ciphertext
  and the envelope key wrapped with the phone's RSA public key using OAEP with SHA-256 and the
  Android-compatible MGF1-SHA-1. [Android cryptography documentation](https://developer.android.com/privacy-and-security/cryptography)
- For each request the phone initializes a new Android Keystore decrypt operation and passes its
  cipher as a `BiometricPrompt.CryptoObject` with `BIOMETRIC_STRONG`. The authenticated operation
  releases only the envelope key. The reply must match the request's random challenge on the
  authenticated connection before its monotonic deadline. The Mac verifies the envelope's
  authentication tag and returns the Bitwarden user key through the requesting browser channel.
  Application-owned plaintext and unsealing buffers are cleared promptly. TLS and system
  providers manage their own buffers. [Android biometric authentication documentation](https://developer.android.com/identity/sign-in/biometric-auth)
- The Bitwarden user key stays on the Mac and in the browser integration. The phone receives
  neither vault data nor the Bitwarden master password. Biometric samples stay within Android.
- The app checks hardware backing and enforcement of biometric authentication on the phone.
  Pairing trusts the phone and app confirmed by the user. This version has no remote device
  attestation. Malware controlling the Mac or phone during an approved unlock could capture
  the released key material. On ad-hoc Mac builds, the original user key still uses WardenFuse's
  login Keychain fallback and its software-enforced authentication check. The separate Android
  envelope retains its cryptographic protection in either Mac signing mode.
- **Remove** under **Paired Devices** revokes the credential and discards its envelope. Logout,
  account replacement and a changed wrapped account key invalidate enrollments. After a
  Bitwarden key rotation, sign out and sign back in to refresh the Mac Keychain key before
  re-pairing. Rotation can only be detected once WardenFuse receives the changed key on sync.
  If Android is reinstalled, the screen lock is reset, or changing biometrics invalidates the
  Keystore key, remove the old registration on the Mac and pair again.
- The phone listens while the app is open. The Mac listens on TCP 47635 on IPv4 while Android
  browser authentication is enabled for an active account. The network must allow local
  peer-to-peer traffic. If the saved Mac address changes, forget the Mac on Android, remove the
  old phone registration on macOS and pair with the new address.

## Verification

Rust tests drive pairing and approval over real TLS with a software phone key, run the key
through both browser handlers, and check invalid proofs, replay, expiry, disconnection,
revocation, account changes and restart recovery. Existing browser tests exercise Native
Messaging and SDK Noise transport. Swift tests exercise LocalAuthentication with mocks.
Android JVM tests cover bounded wire frames and OAEP parameters.

For a hardware check, pair a physical Android phone and unlock the official extension while
watching for the Android system biometric prompt. Repeat with cancellation, a closed phone app
and a revoked registration. Switch the Mac selector back to its native method and verify the
original browser and SSH prompts.
