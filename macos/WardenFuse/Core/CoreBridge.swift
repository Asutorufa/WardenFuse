import AppKit
import CWardenFuseCore
import Foundation
import LocalAuthentication

/// Thin bridge to the Rust core (same process, C ABI). The core owns all state and logic; this
/// class only forwards commands, publishes the latest state snapshot and serves the platform
/// callbacks (Keychain, LocalAuthentication).
@MainActor
final class CoreBridge: ObservableObject {
    static let shared = CoreBridge()

    @Published private(set) var snapshot: Snapshot?
    @Published private(set) var started = false
    @Published private(set) var startError: String?

    let keychain = KeychainStore()
    private(set) lazy var auth: AuthCoordinator = Authenticator.make(keychain: keychain)

    private var nextCommandId: UInt64 = 1
    private var pending: [UInt64: CheckedContinuation<[String: Any], Never>] = [:]

    private init() {}

    var nmhPath: String {
        Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/wardenfuse-nmh").path
    }

    func start() {
        guard !started else { return }
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("WardenFuse", isDirectory: true)
        let config: [String: Any] = [
            "data_dir": support.path,
            "nmh_path": nmhPath,
            "keychain_mode": keychain.mode.rawValue,
        ]
        let json = String(data: try! JSONSerialization.data(withJSONObject: config), encoding: .utf8)!
        let callbacks = WFCallbacks(
            ctx: nil,
            state_changed: wfStateChanged,
            command_result: wfCommandResult,
            auth_request: wfAuthRequest,
            keychain_store: wfKeychainStore,
            keychain_load: wfKeychainLoad,
            keychain_delete: wfKeychainDelete,
            biometry_state: wfBiometryState
        )
        started = json.withCString { wf_start($0, callbacks) }
        if !started {
            startError = "The WardenFuse core failed to start. See Console.app for details."
        }
    }

    func shutdown() {
        guard started else { return }
        // No secret is returned for a request that is still waiting for the user.
        auth.cancelAll()
        wf_shutdown()
    }

    // MARK: Commands

    @discardableResult
    func command(_ cmd: String, _ args: [String: Any] = [:]) async -> [String: Any] {
        guard started else { return ["ok": false, "error": "core not running"] }
        var payload = args
        payload["cmd"] = cmd
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let json = String(data: data, encoding: .utf8) else {
            return ["ok": false, "error": "invalid command"]
        }
        let id = nextCommandId
        nextCommandId += 1
        return await withCheckedContinuation { cont in
            pending[id] = cont
            json.withCString { wf_command(id, $0) }
        }
    }

    func updateSettings(_ s: CoreSettings) async -> (Bool, String?) {
        guard let data = try? WireCoding.encoder.encode(s),
              let obj = try? JSONSerialization.jsonObject(with: data) else { return (false, "encode") }
        let r = await command("update_settings", ["settings": obj])
        return (r["ok"] as? Bool ?? false, r["error"] as? String)
    }

    fileprivate func deliverResult(_ id: UInt64, _ json: String) {
        let obj = (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any] ?? [:]
        pending.removeValue(forKey: id)?.resume(returning: obj)
    }

    func deliverState(_ json: String) {
        do {
            let s = try WireCoding.decoder.decode(Snapshot.self, from: Data(json.utf8))
            if s != snapshot { snapshot = s }
        } catch {
            NSLog("WardenFuse: unable to decode state: \(error)")
        }
    }
}

// MARK: - C callbacks (called on core threads)

private func wfStateChanged(_ ctx: UnsafeMutableRawPointer?, _ json: UnsafePointer<CChar>?) {
    guard let json else { return }
    let s = String(cString: json)
    DispatchQueue.main.async { CoreBridge.shared.deliverState(s) }
}

private func wfCommandResult(_ ctx: UnsafeMutableRawPointer?, _ id: UInt64, _ json: UnsafePointer<CChar>?) {
    let s = json.map { String(cString: $0) } ?? "{}"
    DispatchQueue.main.async { CoreBridge.shared.deliverResult(id, s) }
}

private func wfAuthRequest(_ ctx: UnsafeMutableRawPointer?, _ id: UInt64, _ json: UnsafePointer<CChar>?) {
    guard let json else { wf_auth_complete(id, 2, nil, 0); return }
    let s = String(cString: json)
    DispatchQueue.main.async {
        guard let req = try? WireCoding.decoder.decode(AuthRequestPayload.self, from: Data(s.utf8)) else {
            wf_auth_complete(id, 2, nil, 0)
            return
        }
        CoreBridge.shared.auth.handle(id: id, request: req)
    }
}

/// Keychain operations are synchronous Security.framework calls, safe off the main thread.
private let keychainForCallbacks = KeychainStore()

private func wfKeychainStore(
    _ ctx: UnsafeMutableRawPointer?, _ account: UnsafePointer<CChar>?, _ data: UnsafePointer<UInt8>?,
    _ len: Int, _ protectedItem: Bool
) -> Int32 {
    guard let account, let data else { return Int32(errSecParam) }
    let d = Data(bytes: data, count: len)
    return keychainForCallbacks.store(account: String(cString: account), data: d, protected: protectedItem)
}

private func wfKeychainLoad(
    _ ctx: UnsafeMutableRawPointer?, _ account: UnsafePointer<CChar>?,
    _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, _ outLen: UnsafeMutablePointer<Int>?
) -> Int32 {
    guard let account, let out, let outLen else { return Int32(errSecParam) }
    guard var d = keychainForCallbacks.load(account: String(cString: account)) else {
        return Int32(errSecItemNotFound)
    }
    let buf = malloc(max(d.count, 1))!.assumingMemoryBound(to: UInt8.self)
    d.copyBytes(to: buf, count: d.count)
    d.resetBytes(in: 0..<d.count)
    out.pointee = buf
    outLen.pointee = d.count
    return 0
}

private func wfKeychainDelete(_ ctx: UnsafeMutableRawPointer?, _ account: UnsafePointer<CChar>?) {
    guard let account else { return }
    keychainForCallbacks.delete(account: String(cString: account))
}

private func wfBiometryState(_ ctx: UnsafeMutableRawPointer?) -> Int32 {
    let ctx = LAContext()
    var err: NSError?
    if ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) { return 0 }
    if let e = err as? LAError, e.code == .biometryNotEnrolled { return 1 }
    return 2
}
