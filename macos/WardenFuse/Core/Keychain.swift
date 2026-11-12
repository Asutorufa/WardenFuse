import Foundation
import LocalAuthentication
import Security

/// Keychain storage for the protected Bitwarden user key, session, and Android TLS identity.
///
/// * **Strong mode** (app signed with a Team ID + `keychain-access-groups`): items live in the
///   data protection keychain. The user key item carries a `SecAccessControl` with
///   `.userPresence`; `securityd` only releases it for an `LAContext` that has just been
///   evaluated (`kSecUseAuthenticationContext`). Authentication and key access are bound by
///   the OS, not by a boolean in our process.
/// * **Fallback mode** (ad-hoc signed local builds, where the data protection keychain is not
///   available, `errSecMissingEntitlement`): items live in the login keychain restricted to
///   this app, and the user key is read only after a successful `LAContext` evaluation. This is
///   weaker and is reported as such in Settings → Security.
/// Immutable after init; Security.framework calls are thread safe.
final class KeychainStore: @unchecked Sendable {
    enum Mode: String {
        case strong = "secure_access_control"
        case fallback = "login_keychain_fallback"
    }

    static let service = "io.github.asutorufa.wardenfuse"
    let mode: Mode

    init() {
        mode = KeychainStore.detectMode()
    }

    private static func detectMode() -> Mode {
        let probe: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service + ".probe",
            kSecAttrAccount as String: "probe",
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: Data([0]),
        ]
        SecItemDelete(baseQuery(service + ".probe", "probe", dataProtection: true) as CFDictionary)
        let status = SecItemAdd(probe as CFDictionary, nil)
        SecItemDelete(baseQuery(service + ".probe", "probe", dataProtection: true) as CFDictionary)
        return status == errSecSuccess ? .strong : .fallback
    }

    private static func baseQuery(_ service: String, _ account: String, dataProtection: Bool) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if dataProtection { q[kSecUseDataProtectionKeychain as String] = true }
        return q
    }

    private func query(_ account: String) -> [String: Any] {
        KeychainStore.baseQuery(KeychainStore.service, account, dataProtection: mode == .strong)
    }

    func store(account: String, data: Data, protected: Bool) -> OSStatus {
        SecItemDelete(query(account) as CFDictionary)
        var q = query(account)
        q[kSecValueData as String] = data
        let label = protected ? "Bitwarden key" : account == "android.tls" ? "Android TLS identity" : "session"
        q[kSecAttrLabel as String] = "WardenFuse (\(label))"
        if mode == .strong {
            if protected {
                var err: Unmanaged<CFError>?
                guard let ac = SecAccessControlCreateWithFlags(
                    nil,
                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                    [.userPresence],
                    &err
                ) else { return errSecParam }
                q[kSecAttrAccessControl as String] = ac
            } else {
                q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            }
        }
        return SecItemAdd(q as CFDictionary, nil)
    }

    /// Session or Android TLS identity. Neither item carries the user-presence ACL.
    func load(account: String) -> (Data?, OSStatus) {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        if account == "android.tls" {
            let context = LAContext()
            context.interactionNotAllowed = true
            q[kSecUseAuthenticationContext as String] = context
        }
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        return (out as? Data, status)
    }

    /// Protected item: requires an `LAContext` that was just evaluated by the caller.
    func loadProtected(account: String, context: LAContext) -> (Data?, OSStatus) {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecUseAuthenticationContext as String] = context
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        return (out as? Data, status)
    }

    func delete(account: String) {
        SecItemDelete(query(account) as CFDictionary)
    }
}
