import Foundation
@preconcurrency import LocalAuthentication
import Testing
@testable import WardenFuse

/// Scripted LocalAuthentication stand-in (no Touch ID hardware needed).
final class MockAuthenticator: LocalAuthenticating, @unchecked Sendable {
    enum Script { case success, cancel, fail, never }
    let script: Script
    let available: Bool
    private let lock = NSLock()
    private(set) var evaluatedPolicy: LAPolicy?
    private(set) var reason: String?
    private(set) var invalidated = false
    private(set) var interactionDisallowed = false
    private var pending: (@Sendable (Bool, LAError.Code?) -> Void)?

    init(_ script: Script, available: Bool = true) {
        self.script = script
        self.available = available
    }

    func canEvaluate(_ policy: LAPolicy) -> Bool { available }

    func evaluate(_ policy: LAPolicy, reason: String, completion: @escaping @Sendable (Bool, LAError.Code?) -> Void) {
        lock.lock(); evaluatedPolicy = policy; self.reason = reason; lock.unlock()
        switch script {
        case .success: DispatchQueue.global().async { completion(true, nil) }
        case .cancel: DispatchQueue.global().async { completion(false, .userCancel) }
        case .fail: DispatchQueue.global().async { completion(false, .authenticationFailed) }
        case .never: lock.lock(); pending = completion; lock.unlock()
        }
    }

    func invalidate() {
        lock.lock(); invalidated = true; let p = pending; pending = nil; lock.unlock()
        // Like LAContext: invalidating a running evaluation completes it with appCancel.
        p?(false, .appCancel)
    }

    func disallowInteraction() {
        lock.lock(); interactionDisallowed = true; lock.unlock()
    }
}

final class MockReader: ProtectedKeyReading, @unchecked Sendable {
    let result: (Data?, OSStatus)
    private let lock = NSLock()
    private(set) var reads: [(String, Bool)] = []

    init(_ result: (Data?, OSStatus)) { self.result = result }

    func readProtectedKey(account: String, authenticatedWith auth: LocalAuthenticating) -> (Data?, OSStatus) {
        let m = auth as! MockAuthenticator
        lock.lock(); reads.append((account, m.interactionDisallowed)); lock.unlock()
        return result
    }
}

actor Results {
    var items: [(UInt64, AuthOutcome)] = []
    func add(_ id: UInt64, _ o: AuthOutcome) { items.append((id, o)) }
    func wait(count: Int) async -> [(UInt64, AuthOutcome)] {
        for _ in 0..<400 where items.count < count { try? await Task.sleep(for: .milliseconds(5)) }
        return items
    }
}

func request(kind: String = "ssh_sign", biometrics: Bool = true, password: Bool = true,
             usage: String? = "git", keyName: String? = "Personal", processName: String? = "ssh-keygen",
             processPath: String? = "/usr/bin/ssh-keygen", browser: String? = nil) -> AuthRequestPayload {
    AuthRequestPayload(
        purpose: .init(kind: kind, keyName: keyName, keyFingerprint: "SHA256:x", processName: processName,
                       processPath: processPath, processId: 42, usage: usage, hostKeyFingerprint: nil,
                       forwarded: false, ttlSecs: 600, browser: browser),
        reason: "core reason", userId: "u1", allowBiometrics: biometrics, allowPassword: password)
}

@MainActor
struct AuthCoordinatorTests {
    let key = Data("USERKEY".utf8)

    private func coordinator(_ auth: @escaping () -> MockAuthenticator, reader: MockReader,
                             timeout: Duration = .seconds(5), results: Results) -> AuthCoordinator {
        AuthCoordinator(makeAuthenticator: auth, reader: reader, timeout: timeout) { id, o in
            Task { await results.add(id, o) }
        }
    }

    @Test func successReadsKeychainWithEvaluatedContextAndNoFurtherUI() async {
        let results = Results(); let auth = MockAuthenticator(.success)
        let reader = MockReader((key, errSecSuccess))
        let c = coordinator({ auth }, reader: reader, results: results)
        c.handle(id: 1, request: request())
        let r = await results.wait(count: 1)
        #expect(r.count == 1 && r[0].0 == 1 && r[0].1 == .key(key))
        #expect(reader.reads.count == 1)
        #expect(reader.reads[0].0 == "userkey.u1")
        #expect(reader.reads[0].1, "interaction must be disallowed before the Keychain read")
        #expect(auth.evaluatedPolicy == .deviceOwnerAuthentication)
        try? await Task.sleep(for: .milliseconds(20))
        #expect(!c.hasActiveRequest)
        #expect(auth.invalidated, "context released after use")
    }

    @Test func cancelReturnsNoSecretAndSkipsKeychain() async {
        let results = Results(); let reader = MockReader((key, errSecSuccess))
        let c = coordinator({ MockAuthenticator(.cancel) }, reader: reader, results: results)
        c.handle(id: 2, request: request())
        let r = await results.wait(count: 1)
        #expect(r[0].1 == .cancelled)
        #expect(reader.reads.isEmpty)
    }

    @Test func failureDenies() async {
        let results = Results(); let reader = MockReader((key, errSecSuccess))
        let c = coordinator({ MockAuthenticator(.fail) }, reader: reader, results: results)
        c.handle(id: 3, request: request())
        #expect(await results.wait(count: 1)[0].1 == .failed)
        #expect(reader.reads.isEmpty)
    }

    @Test func keychainFailureAfterSuccessDenies() async {
        let results = Results()
        let c = coordinator({ MockAuthenticator(.success) }, reader: MockReader((nil, errSecInteractionNotAllowed)), results: results)
        c.handle(id: 4, request: request())
        #expect(await results.wait(count: 1)[0].1 == .failed)
        let results2 = Results()
        let c2 = coordinator({ MockAuthenticator(.success) }, reader: MockReader((nil, errSecItemNotFound)), results: results2)
        c2.handle(id: 5, request: request())
        #expect(await results2.wait(count: 1)[0].1 == .keyMissing)
    }

    @Test func timeoutInvalidatesContextAndReportsOnce() async {
        let results = Results(); let auth = MockAuthenticator(.never)
        let c = coordinator({ auth }, reader: MockReader((key, errSecSuccess)), timeout: .milliseconds(50), results: results)
        c.handle(id: 6, request: request())
        let r = await results.wait(count: 1)
        try? await Task.sleep(for: .milliseconds(50))
        #expect(await results.items.count == 1, "exactly one completion")
        #expect(r[0].1 == .timeout)
        #expect(auth.invalidated)
        #expect(!c.hasActiveRequest)
    }

    @Test func concurrentRequestIsRefusedWithoutSecondDialog() async {
        let results = Results(); var created = 0
        let c = coordinator({ created += 1; return MockAuthenticator(.never) }, reader: MockReader((key, errSecSuccess)), results: results)
        c.handle(id: 7, request: request())
        c.handle(id: 8, request: request())
        let r = await results.wait(count: 1)
        #expect(r[0].0 == 8 && r[0].1 == .failed)
        #expect(created == 1, "only one system dialog")
        c.cancelAll()
        let all = await results.wait(count: 2)
        #expect(all.contains { $0.0 == 7 && $0.1 == .cancelled }, "app quit cancels pending request")
    }

    @Test func policyMapping() {
        #expect(AuthPolicySelection.policy(allowBiometrics: true, allowPassword: true) == .deviceOwnerAuthentication)
        #expect(AuthPolicySelection.policy(allowBiometrics: true, allowPassword: false) == .deviceOwnerAuthenticationWithBiometrics)
        #expect(AuthPolicySelection.policy(allowBiometrics: false, allowPassword: true) == nil, "not enforceable")
        #expect(AuthPolicySelection.policy(allowBiometrics: false, allowPassword: false) == nil)
    }

    @Test func touchIDOnlyUsesBiometricPolicyAndUnavailableFailsClosed() async {
        let results = Results(); let auth = MockAuthenticator(.success)
        let c = coordinator({ auth }, reader: MockReader((key, errSecSuccess)), results: results)
        c.handle(id: 9, request: request(password: false))
        _ = await results.wait(count: 1)
        #expect(auth.evaluatedPolicy == .deviceOwnerAuthenticationWithBiometrics)
        let results2 = Results()
        let c2 = coordinator({ MockAuthenticator(.success, available: false) }, reader: MockReader((key, errSecSuccess)), results: results2)
        c2.handle(id: 10, request: request(password: false))
        #expect(await results2.wait(count: 1)[0].1 == .unavailable)
    }

    @Test func reasons() {
        #expect(AuthReason.make(request()) == "sign a Git commit with SSH key \u{201c}Personal\u{201d}")
        #expect(AuthReason.make(request(usage: "ssh", keyName: "GitHub", processName: "ssh", processPath: "/usr/bin/ssh"))
                == "authenticate with SSH key \u{201c}GitHub\u{201d} for ssh")
        #expect(AuthReason.make(request(usage: "ssh", keyName: "GitHub", processName: "ssh", processPath: nil))
                == "authenticate with SSH key \u{201c}GitHub\u{201d}", "unverified process is not shown")
        #expect(AuthReason.make(request(kind: "browser_unlock", browser: "Brave Browser")) == "unlock Bitwarden in Brave Browser")
        #expect(AuthReason.make(request(kind: "browser_unlock", browser: "")) == "unlock Bitwarden in your browser")
        #expect(AuthReason.make(request(kind: "agent_unlock")) == "unlock the WardenFuse SSH agent")
        let long = AuthReason.make(request(keyName: String(repeating: "k", count: 80)))
        #expect(long.count < 80)
    }
}
