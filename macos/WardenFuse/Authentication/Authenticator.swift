import AppKit
import CWardenFuseCore
@preconcurrency import Dispatch
@preconcurrency import LocalAuthentication
import SwiftUI

/// Serves authentication requests from the core.
///
/// For every request: show a small panel describing *what* is being authorized (key, verified
/// requesting executable, usage, TTL), evaluate an `LAContext` (Touch ID, macOS password as
/// fallback when allowed — the system's own UI, never an app-made password field), then read the
/// protected Keychain item with that context and hand the bytes to the core. Cancellation,
/// failure and timeout all fail closed.
@MainActor
final class Authenticator {
    private var panel: NSPanel?
    private var activeContext: LAContext?

    func handle(id: UInt64, request: AuthRequestPayload, keychain: KeychainStore) {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedCancelTitle = "Cancel"
        activeContext = context

        let policy: LAPolicy
        switch (request.allowBiometrics, request.allowPassword) {
        case (true, false): policy = .deviceOwnerAuthenticationWithBiometrics
        default: policy = .deviceOwnerAuthentication
        }
        var canErr: NSError?
        guard context.canEvaluatePolicy(policy, error: &canErr) else {
            complete(id, status: 3)
            return
        }

        showPanel(request: request) { [weak self] in
            context.invalidate()
            self?.closePanel()
        }

        // Safety net: never leave a dialog open longer than the core waits.
        let timeout = DispatchWorkItem { context.invalidate() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 85, execute: timeout)

        context.evaluatePolicy(policy, localizedReason: request.reason) { success, error in
            DispatchQueue.main.async {
                timeout.cancel()
                defer {
                    self.closePanel()
                    self.activeContext = nil
                }
                guard success else {
                    let code = (error as? LAError)?.code
                    let cancelled = code == .userCancel || code == .appCancel || code == .systemCancel
                    self.complete(id, status: cancelled ? 1 : 2)
                    return
                }
                // The key is only released by securityd for this evaluated context (strong
                // mode), so success here is backed by the OS, not by our boolean.
                let (data, status) = keychain.loadProtected(account: "userkey.\(request.userId)", context: context)
                guard var data, status == errSecSuccess else {
                    self.complete(id, status: status == errSecItemNotFound ? 4 : 2)
                    return
                }
                data.withUnsafeBytes { buf in
                    wf_auth_complete(id, 0, buf.bindMemory(to: UInt8.self).baseAddress, buf.count)
                }
                data.resetBytes(in: 0..<data.count)
            }
        }
    }

    private func complete(_ id: UInt64, status: Int32) {
        wf_auth_complete(id, status, nil, 0)
    }

    private func showPanel(request: AuthRequestPayload, onCancel: @escaping () -> Void) {
        closePanel()
        let view = AuthPanelView(request: request, onCancel: onCancel)
        let hosting = NSHostingController(rootView: view)
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 380, height: 10),
            styleMask: [.titled, .fullSizeContentView, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isMovableByWindowBackground = true
        panel.contentViewController = hosting
        panel.level = .modalPanel
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.setContentSize(hosting.view.fittingSize)
        if let screen = NSScreen.main {
            let f = screen.visibleFrame
            panel.setFrameTopLeftPoint(NSPoint(x: f.midX - panel.frame.width / 2, y: f.maxY - 80))
        }
        NSApp.activate(ignoringOtherApps: true)
        panel.orderFrontRegardless()
        self.panel = panel
    }

    private func closePanel() {
        panel?.orderOut(nil)
        panel?.contentViewController = nil
        panel = nil
    }
}

struct AuthPanelView: View {
    let request: AuthRequestPayload
    let onCancel: () -> Void

    private var title: String {
        switch request.purpose.kind {
        case "ssh_sign": return "SSH key requested"
        case "ssh_list": return "List SSH keys"
        case "agent_unlock": return "Unlock SSH agent"
        case "browser_unlock": return "Unlock Bitwarden"
        case "browser_verify": return "Verify your identity"
        default: return "WardenFuse"
        }
    }

    private var usage: String? {
        switch request.purpose.usage {
        case "git": return "Git signing (SSHSIG namespace “git”)"
        case "file": return "File signing (SSHSIG namespace “file”)"
        case "sshsig": return "SSH signature (other namespace)"
        case "ssh": return "SSH authentication"
        default: return nil
        }
    }

    private func ttlText(_ s: UInt64) -> String {
        if s == 0 { return "This request only" }
        if s % 3600 == 0 { return "\(s / 3600) h for this key and app" }
        if s % 60 == 0 { return "\(s / 60) min for this key and app" }
        return "\(s) s for this key and app"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: request.purpose.kind.hasPrefix("browser") ? "lock.open" : "key.horizontal")
                    .font(.title2)
                    .foregroundStyle(.secondary)
                Text(title).font(.headline)
            }
            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 4) {
                if let k = request.purpose.keyName {
                    row("Key", k)
                }
                if let fp = request.purpose.keyFingerprint {
                    row("Fingerprint", fp, mono: true)
                }
                if request.purpose.kind == "ssh_sign" {
                    if let p = request.purpose.processName {
                        row("Requested by", p + (request.purpose.processId.map { " (pid \($0))" } ?? ""))
                        if let path = request.purpose.processPath { row("", path, mono: true) }
                    } else {
                        row("Requested by", "Unknown process (not verifiable)")
                    }
                }
                if let u = usage { row("Usage", u) }
                if let h = request.purpose.hostKeyFingerprint, !h.isEmpty {
                    row("Host key", h, mono: true)
                }
                if request.purpose.forwarded == true {
                    row("Forwarded", "Request came through agent forwarding")
                }
                if let b = request.purpose.browser { row("Browser", b) }
                if let t = request.purpose.ttlSecs, request.purpose.kind == "ssh_sign" || request.purpose.kind == "agent_unlock" {
                    row("Valid for", request.purpose.kind == "agent_unlock" && t > 0 ? ttlText(t).replacingOccurrences(of: " for this key and app", with: " for all keys") : ttlText(t))
                }
            }
            .font(.callout)
            Text("Confirm with Touch ID or your macOS password.")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(16)
        .frame(width: 380)
    }

    @ViewBuilder
    private func row(_ label: String, _ value: String, mono: Bool = false) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value)
                .font(mono ? .caption.monospaced() : .callout)
                .textSelection(.enabled)
                .lineLimit(2)
                .truncationMode(.middle)
        }
    }
}
