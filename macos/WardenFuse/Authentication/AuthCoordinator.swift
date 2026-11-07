import Foundation
@preconcurrency import LocalAuthentication

/// Result of one authentication request, delivered to the Rust core exactly once.
enum AuthOutcome: Equatable {
    case key(Data)
    case cancelled
    case failed
    case unavailable
    case keyMissing
    case timeout

    /// Status codes of `wf_auth_complete` (crates/wardenfuse-core/src/ffi.rs).
    var ffiStatus: Int32 {
        switch self {
        case .key: return 0
        case .cancelled: return 1
        case .failed: return 2
        case .unavailable: return 3
        case .keyMissing: return 4
        case .timeout: return 6
        }
    }
}

/// One LocalAuthentication evaluation. Implemented by `LAContext` in the app and by mocks in
/// tests.
protocol LocalAuthenticating: AnyObject, Sendable {
    func canEvaluate(_ policy: LAPolicy) -> Bool
    /// Shows the system authentication UI. `completion` is called once, on any thread.
    func evaluate(_ policy: LAPolicy, reason: String, completion: @escaping @Sendable (Bool, LAError.Code?) -> Void)
    /// Cancels a running evaluation (the system UI disappears) and invalidates the context.
    func invalidate()
    /// After a successful evaluation: forbid any further UI from this context, so that the
    /// Keychain read can never show a second dialog (it fails with `errSecInteractionNotAllowed`
    /// instead).
    func disallowInteraction()
}

/// Reads the protected user key with an evaluated authentication context.
protocol ProtectedKeyReading: Sendable {
    func readProtectedKey(account: String, authenticatedWith auth: LocalAuthenticating) -> (Data?, OSStatus)
}

/// Maps the Security settings to a LocalAuthentication policy.
///
/// macOS offers no public policy for "password only": `.deviceOwnerAuthentication` always
/// prefers Touch ID when it is available. That combination is therefore rejected (the core's
/// settings validation does not allow it either) instead of silently using Touch ID.
enum AuthPolicySelection {
    static func policy(allowBiometrics: Bool, allowPassword: Bool) -> LAPolicy? {
        switch (allowBiometrics, allowPassword) {
        case (true, true): return .deviceOwnerAuthentication            // Touch ID, password fallback
        case (true, false): return .deviceOwnerAuthenticationWithBiometrics // Touch ID only
        default: return nil
        }
    }
}

/// Builds the short `localizedReason` shown by the system dialog
/// ("“WardenFuse” is trying to <reason>.").
///
/// Only facts the core verified are used: the key name from the vault, the SSHSIG namespace the
/// agent parsed, the executable resolved from the kernel peer credentials, and the browser that
/// launched the bundled native messaging host. Nothing is shown when it could not be verified.
enum AuthReason {
    static let maxKeyName = 32

    static func make(_ r: AuthRequestPayload) -> String {
        let p = r.purpose
        switch p.kind {
        case "ssh_sign":
            let key = "SSH key \u{201c}\(shorten(p.keyName ?? "unnamed"))\u{201d}"
            var reason: String
            switch p.usage {
            case "git": reason = "sign a Git commit with \(key)"
            case "file": reason = "sign a file with \(key)"
            case "sshsig": reason = "create a signature with \(key)"
            default:
                reason = "authenticate with \(key)"
                // Process name only when the kernel gave us an executable path.
                if p.processPath != nil, let name = p.processName, !name.isEmpty {
                    reason += " for \(shorten(name))"
                }
            }
            if p.forwarded == true { reason += " (forwarded request)" }
            return reason
        case "ssh_list":
            return "show the SSH keys in your Bitwarden vault"
        case "agent_unlock":
            return "unlock the WardenFuse SSH agent"
        case "browser_unlock":
            return "unlock Bitwarden in \(browser(p.browser))"
        case "browser_verify":
            return "verify your identity for \(browser(p.browser))"
        default:
            return r.reason.isEmpty ? "access your Bitwarden key" : r.reason
        }
    }

    private static func browser(_ name: String?) -> String {
        guard let n = name?.trimmingCharacters(in: .whitespaces), !n.isEmpty, n != "your browser" else {
            return "your browser"
        }
        return shorten(n)
    }

    static func shorten(_ s: String) -> String {
        s.count <= maxKeyName ? s : String(s.prefix(maxKeyName - 1)) + "\u{2026}"
    }
}

/// Serves authentication requests from the core with the macOS system UI only.
///
/// Flow: choose policy → `evaluatePolicy` (system Touch ID / password dialog) → on success,
/// forbid further interaction on that context → read the `SecAccessControl(.userPresence)`
/// Keychain item with the evaluated context → hand the bytes to the core. The bytes are the
/// proof of authentication; there is no "authenticated" boolean the UI could fake.
@MainActor
final class AuthCoordinator {
    typealias Complete = @Sendable (UInt64, AuthOutcome) -> Void

    private let makeAuthenticator: () -> LocalAuthenticating
    private let reader: ProtectedKeyReading
    private let complete: Complete
    private let timeout: Duration

    private var active: Session?

    init(
        makeAuthenticator: @escaping () -> LocalAuthenticating,
        reader: ProtectedKeyReading,
        timeout: Duration = .seconds(85),
        complete: @escaping Complete
    ) {
        self.makeAuthenticator = makeAuthenticator
        self.reader = reader
        self.timeout = timeout
        self.complete = complete
    }

    var hasActiveRequest: Bool { active != nil }

    func handle(id: UInt64, request: AuthRequestPayload) {
        // The core serializes prompts; a second concurrent request is refused (fail closed)
        // rather than stacking dialogs.
        guard active == nil else {
            complete(id, .failed)
            return
        }
        guard let policy = AuthPolicySelection.policy(
            allowBiometrics: request.allowBiometrics, allowPassword: request.allowPassword
        ) else {
            complete(id, .unavailable)
            return
        }
        let auth = makeAuthenticator()
        guard auth.canEvaluate(policy) else {
            complete(id, .unavailable)
            return
        }

        let session = Session(id: id, auth: auth, complete: complete)
        active = session
        let reader = self.reader
        let account = "userkey.\(request.userId)"

        session.timeoutTask = Task { [weak self, timeout] in
            try? await Task.sleep(for: timeout)
            guard !Task.isCancelled else { return }
            session.finish(.timeout)
            self?.release(session)
        }

        auth.evaluate(policy, reason: AuthReason.make(request)) { [weak self] success, code in
            if success {
                auth.disallowInteraction()
                let (data, status) = reader.readProtectedKey(account: account, authenticatedWith: auth)
                if let data, status == errSecSuccess, !data.isEmpty {
                    session.finish(.key(data))
                } else {
                    session.finish(status == errSecItemNotFound ? .keyMissing : .failed)
                }
            } else {
                switch code {
                case .userCancel, .appCancel, .systemCancel: session.finish(.cancelled)
                case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet: session.finish(.unavailable)
                default: session.finish(.failed)
                }
            }
            Task { @MainActor in self?.release(session) }
        }
    }

    /// Cancels the pending request (app termination). No secret is returned.
    func cancelAll() {
        guard let s = active else { return }
        s.finish(.cancelled)
        release(s)
    }

    private func release(_ session: Session) {
        session.timeoutTask?.cancel()
        session.auth.invalidate()
        if active === session { active = nil }
    }

    /// Guarantees exactly one completion per request, whichever of result / timeout / cancel
    /// happens first.
    final class Session: @unchecked Sendable {
        let id: UInt64
        let auth: LocalAuthenticating
        private let complete: Complete
        private let lock = NSLock()
        private var done = false
        var timeoutTask: Task<Void, Never>?

        init(id: UInt64, auth: LocalAuthenticating, complete: @escaping Complete) {
            self.id = id
            self.auth = auth
            self.complete = complete
        }

        func finish(_ outcome: AuthOutcome) {
            lock.lock()
            let first = !done
            done = true
            lock.unlock()
            guard first else { return }
            if case .timeout = outcome { auth.invalidate() }
            if case .cancelled = outcome { auth.invalidate() }
            complete(id, outcome)
        }
    }
}
