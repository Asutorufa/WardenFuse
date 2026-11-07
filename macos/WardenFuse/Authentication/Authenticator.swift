import CWardenFuseCore
import Foundation
@preconcurrency import LocalAuthentication
import Security

/// `LAContext` adapter: the system Touch ID / macOS password dialog is the only UI.
final class SystemLocalAuthenticator: LocalAuthenticating, @unchecked Sendable {
    let context: LAContext

    init() {
        context = LAContext()
        // Every request is a fresh authentication; never reuse a recent unlock.
        context.touchIDAuthenticationAllowableReuseDuration = 0
    }

    func canEvaluate(_ policy: LAPolicy) -> Bool {
        var error: NSError?
        return context.canEvaluatePolicy(policy, error: &error)
    }

    func evaluate(_ policy: LAPolicy, reason: String, completion: @escaping @Sendable (Bool, LAError.Code?) -> Void) {
        context.evaluatePolicy(policy, localizedReason: reason) { success, error in
            completion(success, (error as? LAError)?.code)
        }
    }

    func invalidate() {
        context.invalidate()
    }

    func disallowInteraction() {
        context.interactionNotAllowed = true
    }
}

extension KeychainStore: ProtectedKeyReading {
    func readProtectedKey(account: String, authenticatedWith auth: LocalAuthenticating) -> (Data?, OSStatus) {
        guard let system = auth as? SystemLocalAuthenticator else { return (nil, errSecAuthFailed) }
        return loadProtected(account: account, context: system.context)
    }
}

/// Production wiring of `AuthCoordinator` to the Rust core.
enum Authenticator {
    @MainActor
    static func make(keychain: KeychainStore) -> AuthCoordinator {
        AuthCoordinator(
            makeAuthenticator: { SystemLocalAuthenticator() },
            reader: keychain,
            complete: { id, outcome in
                switch outcome {
                case .key(var data):
                    data.withUnsafeBytes { buf in
                        wf_auth_complete(id, 0, buf.bindMemory(to: UInt8.self).baseAddress, buf.count)
                    }
                    data.resetBytes(in: 0..<data.count)
                default:
                    wf_auth_complete(id, outcome.ffiStatus, nil, 0)
                }
            }
        )
    }
}
