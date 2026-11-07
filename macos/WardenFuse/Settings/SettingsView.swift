import AppKit
import SwiftUI

/// Native Settings window. Every change is submitted to the core, which validates and applies
/// it; the form always reflects what the core reports back.
struct SettingsView: View {
    @EnvironmentObject var core: CoreBridge

    var body: some View {
        Group {
            if let s = core.snapshot {
                TabView {
                    GeneralTab(s: s).tabItem { Label("General", systemImage: "gearshape") }
                    BitwardenTab(s: s).tabItem { Label("Bitwarden", systemImage: "person.crop.circle") }
                    BrowserTab(s: s).tabItem { Label("Browser", systemImage: "globe") }
                    SSHTab(s: s).tabItem { Label("SSH Agent", systemImage: "terminal") }
                    SecurityTab(s: s).tabItem { Label("Security", systemImage: "lock.shield") }
                }
            } else {
                Text(core.startError ?? "Starting…").padding()
            }
        }
        .frame(width: 560)
        .frame(minHeight: 420)
    }
}

/// Edits a copy of the settings and submits it; shows validation errors from the core.
@MainActor
final class SettingsEditor: ObservableObject {
    @Published var error: String?

    func apply(_ change: (inout CoreSettings) -> Void) {
        guard var s = CoreBridge.shared.snapshot?.settings else { return }
        change(&s)
        Task {
            let (ok, err) = await CoreBridge.shared.updateSettings(s)
            self.error = ok ? nil : err
        }
    }

    func binding<T>(_ s: CoreSettings, _ kp: WritableKeyPath<CoreSettings, T>) -> Binding<T> {
        Binding(get: { s[keyPath: kp] }, set: { v in self.apply { $0[keyPath: kp] = v } })
    }
}

private struct ErrorFooter: View {
    @ObservedObject var editor: SettingsEditor
    var body: some View {
        if let e = editor.error {
            Text(e).font(.callout).foregroundStyle(.red)
        }
    }
}

// MARK: General

private struct GeneralTab: View {
    let s: Snapshot
    @StateObject private var editor = SettingsEditor()
    @AppStorage("showMenuBarIcon") private var showIcon = true
    @State private var loginItemError: String?

    var body: some View {
        Form {
            Section {
                Toggle("Launch at login", isOn: Binding(
                    get: { s.settings.launchAtLogin },
                    set: { v in
                        do {
                            try LoginItem.set(v)
                            loginItemError = LoginItem.requiresApproval
                                ? "Approve WardenFuse in System Settings → General → Login Items." : nil
                            editor.apply { $0.launchAtLogin = LoginItem.isEnabled || LoginItem.requiresApproval }
                        } catch {
                            loginItemError = error.localizedDescription
                        }
                    }))
                if let e = loginItemError { Text(e).font(.caption).foregroundStyle(.secondary) }
                Toggle("Show menu bar icon", isOn: Binding(
                    get: { showIcon },
                    set: { v in showIcon = v; editor.apply { $0.showMenuBarIcon = v } }))
                if !showIcon {
                    Text("Open WardenFuse from Finder or Spotlight to get back to Settings.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Section("Status") {
                LabeledContent("Core") { Text(core.started ? "Running in this app" : "Stopped") }
                LabeledContent("SSH agent") { Text(s.ssh.running ? "Listening" : "Stopped") }
                LabeledContent("Browser bridge") {
                    Text(s.browser.bridgeRunning ? "Ready (\(s.browser.connections) connected)" : "Off")
                }
                Text("WardenFuse runs as a single menu bar app. The SSH agent and browser unlock work while the app is running, also when no window is open. Quitting WardenFuse stops them.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ErrorFooter(editor: editor)
        }
        .formStyle(.grouped)
    }

    private var core: CoreBridge { CoreBridge.shared }
}

// MARK: Bitwarden

private struct BitwardenTab: View {
    let s: Snapshot
    @StateObject private var editor = SettingsEditor()
    @Environment(\.openWindow) private var openWindow
    @State private var confirmLogout = false

    var body: some View {
        Form {
            Section("Account") {
                if s.account.loggedIn {
                    LabeledContent("Email", value: s.account.email ?? "—")
                    LabeledContent("Server", value: s.account.serverUrl)
                    if s.account.sessionExpired {
                        Text("The session expired. Log in again to resume sync.")
                            .foregroundStyle(.orange)
                    }
                    HStack {
                        Spacer()
                        Button("Log In Again…") { openWindow(id: "login") }
                        Button("Log Out", role: .destructive) { confirmLogout = true }
                    }
                } else {
                    HStack {
                        Text("Not logged in").foregroundStyle(.secondary)
                        Spacer()
                        Button("Log In…") { openWindow(id: "login") }
                    }
                }
            }
            Section("Synchronization") {
                Toggle("Automatic sync (live notifications)", isOn: editor.binding(s.settings, \.autoSync))
                Picker("Fallback sync interval", selection: editor.binding(s.settings, \.fallbackSyncIntervalSecs)) {
                    Text("1 minute").tag(UInt64(60))
                    Text("5 minutes").tag(UInt64(300))
                    Text("15 minutes").tag(UInt64(900))
                    Text("1 hour").tag(UInt64(3600))
                }
                Picker("Disable cached keys after offline for", selection: editor.binding(s.settings, \.maxOfflineHours)) {
                    Text("24 hours").tag(UInt64(24))
                    Text("3 days").tag(UInt64(72))
                    Text("7 days").tag(UInt64(168))
                    Text("30 days").tag(UInt64(720))
                }
                LabeledContent("Last successful sync") {
                    if let t = s.sync.lastSuccessUnix {
                        Text(Date(timeIntervalSince1970: TimeInterval(t)), style: .relative) + Text(" ago")
                    } else { Text("Never") }
                }
                LabeledContent("Status") {
                    Text(s.sync.syncing ? "Syncing…" : (s.sync.error ?? (s.sync.notificationsConnected ? "Live updates connected" : "Idle")))
                        .lineLimit(3)
                }
                HStack {
                    Spacer()
                    Button("Sync Now") { Task { await CoreBridge.shared.command("sync_now") } }
                        .disabled(!s.account.loggedIn || s.sync.syncing)
                }
            }
            ErrorFooter(editor: editor)
        }
        .formStyle(.grouped)
        .confirmationDialog("Log out of Bitwarden?", isPresented: $confirmLogout) {
            Button("Log Out", role: .destructive) { Task { await CoreBridge.shared.command("logout") } }
        } message: {
            Text("The vault key, session and cached SSH keys are removed from this Mac. SSH keys and browser unlock stop working until you log in again.")
        }
    }
}

// MARK: Browser

private struct BrowserTab: View {
    let s: Snapshot
    @StateObject private var editor = SettingsEditor()
    @State private var replaceTarget: Snapshot.Manifest?
    @State private var message: String?

    var body: some View {
        Form {
            Section {
                Toggle("Enable browser biometric unlock", isOn: editor.binding(s.settings, \.browserUnlockEnabled))
                LabeledContent("Status") {
                    Text(!s.browser.enabled ? "Disabled" : s.browser.bridgeRunning ? "Ready" : (s.browser.error ?? "Not running"))
                }
            } footer: {
                Text("Use the official Bitwarden extension: Settings → Account security → Unlock with biometrics. Each unlock asks for Touch ID or your password; it is never covered by the SSH authorization time.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Supported browsers") {
                ForEach(s.browser.manifests.filter { $0.state != "browser_not_found" }) { m in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(m.browser.name)
                            Text(stateText(m)).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        switch m.state {
                        case "installed":
                            Button("Remove") { run("uninstall_browser", ["browser": m.browser.id]) }
                        case "foreign":
                            Button("Use WardenFuse…") { replaceTarget = m }
                        default:
                            Button(m.state == "stale" ? "Repair" : "Install") {
                                run("install_browser", ["browser": m.browser.id])
                            }
                        }
                    }
                }
                if s.browser.manifests.allSatisfy({ $0.state == "browser_not_found" }) {
                    Text("No supported Chromium browser found (Chrome, Brave, Edge, Chromium, Vivaldi).")
                        .foregroundStyle(.secondary)
                }
            }
            Section("Diagnostics") {
                LabeledContent("Native messaging host") {
                    Text(s.browser.nmhPath).font(.caption.monospaced()).textSelection(.enabled).lineLimit(2)
                }
                LabeledContent("Connected browsers", value: "\(s.browser.connections)")
                if let message { Text(message).font(.callout) }
            }
            ErrorFooter(editor: editor)
        }
        .formStyle(.grouped)
        .confirmationDialog("Replace the existing Bitwarden connection?", isPresented: Binding(
            get: { replaceTarget != nil }, set: { if !$0 { replaceTarget = nil } }), presenting: replaceTarget) { m in
            Button("Use WardenFuse for \(m.browser.name)") {
                run("install_browser", ["browser": m.browser.id, "replace": true])
            }
        } message: { m in
            Text("\(m.browser.name) is connected to another app (\(m.path ?? "unknown")), usually Bitwarden Desktop. WardenFuse keeps a backup and restores it when you remove WardenFuse’s connection.")
        }
    }

    private func stateText(_ m: Snapshot.Manifest) -> String {
        switch m.state {
        case "installed": return "Connected to WardenFuse"
        case "not_installed": return "Not set up"
        case "stale": return "Points to another copy of WardenFuse"
        case "foreign": return "Used by another app (Bitwarden Desktop?)"
        case "invalid": return "Invalid manifest"
        default: return m.state
        }
    }

    private func run(_ cmd: String, _ args: [String: Any]) {
        Task {
            let r = await CoreBridge.shared.command(cmd, args)
            message = (r["ok"] as? Bool == true) ? "Done. Restart the browser if the extension does not connect." : (r["error"] as? String)
        }
    }
}

// MARK: SSH

private struct SSHTab: View {
    let s: Snapshot
    @StateObject private var editor = SettingsEditor()
    @State private var socketDraft = ""
    @State private var snippet = ""
    @State private var gitSnippet = ""
    @State private var customTTL = ""
    @State private var confirmConfig = false
    @State private var message: String?

    private static let ttlOptions: [(String, UInt64)] = [
        ("Every time", 0), ("1 minute", 60), ("5 minutes", 300), ("10 minutes", 600),
        ("30 minutes", 1800), ("1 hour", 3600),
    ]

    var body: some View {
        Form {
            Section {
                Toggle("Enable SSH agent", isOn: editor.binding(s.settings, \.sshAgentEnabled))
                LabeledContent("Socket") {
                    HStack {
                        TextField("", text: $socketDraft)
                            .font(.caption.monospaced())
                            .onSubmit { editor.apply { $0.sshSocketPath = socketDraft } }
                        Button { copy(s.ssh.socket) } label: { Image(systemName: "doc.on.doc") }
                            .help("Copy path")
                    }
                }
                LabeledContent("Keys", value: "\(s.ssh.keys.count) of \(s.ssh.vaultKeyCount) in vault")
                if !s.ssh.keys.isEmpty {
                    ForEach(s.ssh.keys) { k in
                        HStack {
                            Image(systemName: k.unlocked ? "key.fill" : "key").foregroundStyle(.secondary)
                            Text(k.name)
                            Spacer()
                            Button { copy(k.publicKey) } label: { Image(systemName: "doc.on.doc") }
                                .buttonStyle(.borderless).help("Copy public key")
                        }
                    }
                }
            }
            Section {
                Picker("Ask for Touch ID / password", selection: Binding(
                    get: { s.settings.sshApprovalPolicy == "every_time" ? 0 : s.settings.sshTtlSecs },
                    set: { v in editor.apply {
                        $0.sshApprovalPolicy = v == 0 ? "every_time" : "cache_for_ttl"
                        $0.sshTtlSecs = v
                    } })) {
                    ForEach(Self.ttlOptions, id: \.1) { Text($0.0).tag($0.1) }
                    if !Self.ttlOptions.contains(where: { $0.1 == s.settings.sshTtlSecs }) && s.settings.sshApprovalPolicy != "every_time" {
                        Text("Custom (\(s.settings.sshTtlSecs) s)").tag(s.settings.sshTtlSecs)
                    }
                }
                HStack {
                    TextField("Custom TTL (seconds)", text: $customTTL)
                    Button("Set") {
                        if let v = UInt64(customTTL) {
                            editor.apply { $0.sshTtlSecs = v; $0.sshApprovalPolicy = v == 0 ? "every_time" : "cache_for_ttl" }
                        }
                    }
                }
                Picker("Authorization scope", selection: editor.binding(s.settings, \.sshScopeMode)) {
                    Text("Per key and requesting app").tag("key_and_process")
                    Text("Per key").tag("key")
                }
                Toggle("List public keys while locked", isOn: editor.binding(s.settings, \.listKeysWhenLocked))
                Toggle("Allow agent forwarding", isOn: editor.binding(s.settings, \.allowAgentForwarding))
            } header: {
                Text("Authentication")
            } footer: {
                Text("The time starts when you authenticate and is not extended by signing. Changing these settings revokes current authorizations.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("SSH integration") {
                Text(snippet).font(.caption.monospaced()).textSelection(.enabled)
                HStack {
                    Button("Copy SSH Configuration") { copy(snippet) }
                    Spacer()
                    if s.ssh.sshConfigInstalled {
                        Button("Remove from ~/.ssh/config") { run("uninstall_ssh_config") }
                    } else {
                        Button("Add to ~/.ssh/config…") { confirmConfig = true }
                    }
                }
                DisclosureGroup("Git commit signing") {
                    Text(gitSnippet).font(.caption.monospaced()).textSelection(.enabled)
                    Button("Copy") { copy(gitSnippet) }
                }
                if let message { Text(message).font(.callout) }
            }
            ErrorFooter(editor: editor)
        }
        .formStyle(.grouped)
        .onAppear { socketDraft = s.settings.sshSocketPath; loadSnippet() }
        .onChange(of: s.settings.sshSocketPath) { _, v in socketDraft = v; loadSnippet() }
        .confirmationDialog("Add WardenFuse to ~/.ssh/config?", isPresented: $confirmConfig) {
            Button("Add") { run("install_ssh_config") }
        } message: {
            Text("A clearly marked block with “Host * / IdentityAgent” is added at the top. A backup of the current file is kept and existing entries are not changed.")
        }
    }

    private func loadSnippet() {
        Task {
            let r = await CoreBridge.shared.command("ssh_config_snippet")
            snippet = r["ssh_config"] as? String ?? ""
            gitSnippet = r["git_signing"] as? String ?? ""
        }
    }

    private func run(_ cmd: String) {
        Task {
            let r = await CoreBridge.shared.command(cmd)
            message = (r["ok"] as? Bool == true) ? "Done." : (r["error"] as? String)
        }
    }
}

// MARK: Security

private struct SecurityTab: View {
    let s: Snapshot
    @StateObject private var editor = SettingsEditor()
    @State private var confirmReset = false
    @State private var confirmUninstall = false

    var body: some View {
        Form {
            Section("Authentication") {
                Toggle("Prefer Touch ID", isOn: editor.binding(s.settings, \.preferTouchId))
                Toggle("Allow macOS password fallback", isOn: editor.binding(s.settings, \.allowPasswordFallback))
                LabeledContent("Touch ID") { Text(biometryText) }
                LabeledContent("Keychain protection") {
                    Text(s.security.keychainMode == "secure_access_control"
                         ? "Access control (user presence required)"
                         : "Login keychain (reduced: ad-hoc signed build)")
                }
            }
            Section("Lock the SSH agent") {
                Toggle("When the screen locks", isOn: editor.binding(s.settings, \.lockOnScreenLock))
                Toggle("When the Mac sleeps", isOn: editor.binding(s.settings, \.lockOnSleep))
                Toggle("When switching users", isOn: editor.binding(s.settings, \.lockOnUserSwitch))
                Toggle("Clear authorizations on account switch", isOn: .constant(true)).disabled(true)
                    .help("Always on: switching accounts discards all keys and authorizations.")
            }
            Section("Maintenance") {
                HStack {
                    Button("Reset Local Authentication State…") { confirmReset = true }
                    Spacer()
                    Button("Remove WardenFuse Data…", role: .destructive) { confirmUninstall = true }
                }
            }
            ErrorFooter(editor: editor)
        }
        .formStyle(.grouped)
        .confirmationDialog("Reset local authentication state?", isPresented: $confirmReset) {
            Button("Reset") { Task { await CoreBridge.shared.command("reset_local_auth") } }
        } message: {
            Text("All SSH authorizations and decrypted keys are discarded and browser connections must reconnect.")
        }
        .confirmationDialog("Remove all WardenFuse data?", isPresented: $confirmUninstall) {
            Button("Remove and Quit", role: .destructive) {
                Task {
                    try? LoginItem.set(false)
                    await CoreBridge.shared.command("uninstall")
                    NSApp.terminate(nil)
                }
            }
        } message: {
            Text("Logs out, deletes WardenFuse's Keychain items, cache and settings, removes its browser connections (restoring Bitwarden Desktop's if it was replaced) and its ~/.ssh/config block. Other apps are not touched. Afterwards move WardenFuse.app to the Trash.")
        }
    }

    private var biometryText: String {
        switch s.security.biometry {
        case "available": return "Available"
        case "not_enrolled": return "No fingerprints enrolled"
        default: return "Unavailable (password will be used)"
        }
    }
}

func copy(_ s: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(s, forType: .string)
}
