import AppKit
import SwiftUI

/// Settings panes and navigation state. The window itself (sidebar + detail, toolbar) is built
/// with AppKit split-view primitives in `SettingsWindowController`, like System Settings.
enum SettingsView {
    enum Pane: String, CaseIterable, Identifiable, Hashable {
        case general, bitwarden, browser, ssh, security
        var id: String { rawValue }
        var title: String {
            switch self {
            case .general: "General"
            case .bitwarden: "Bitwarden"
            case .browser: "Browser"
            case .ssh: "SSH Agent"
            case .security: "Security"
            }
        }
        var symbol: String {
            switch self {
            case .general: "gearshape.fill"
            case .bitwarden: "person.crop.circle.fill"
            case .browser: "globe"
            case .ssh: "terminal.fill"
            case .security: "lock.shield.fill"
            }
        }
        var tint: Color {
            switch self {
            case .general: .gray
            case .bitwarden: .blue
            case .browser: .teal
            case .ssh: Color(white: 0.25)
            case .security: .indigo
            }
        }
        var summary: String {
            switch self {
            case .general: "Start at login, the menu bar icon and the status of WardenFuse."
            case .bitwarden: "Your Bitwarden account, server and vault synchronization."
            case .browser: "Unlock the official Bitwarden browser extension with Touch ID."
            case .ssh: "Serve the SSH keys in your vault to ssh, Git and other tools."
            case .security: "How WardenFuse authenticates you and protects your keys."
            }
        }
        var keywords: String {
            switch self {
            case .general: "login launch menu bar icon status"
            case .bitwarden: "account server url sync login logout email vaultwarden"
            case .browser: "chrome brave edge native messaging extension biometrics"
            case .ssh: "socket ttl scope forwarding ssh config git signing keys"
            case .security: "touch id password keychain lock sleep reset"
            }
        }
    }
}

/// Selection with back/forward history, shared by the sidebar, the detail and the toolbar.
@MainActor
final class SettingsNavigation: ObservableObject {
    @Published private(set) var selection: SettingsView.Pane
    @Published private(set) var canGoBack = false
    @Published private(set) var canGoForward = false
    @Published var query = ""
    private var back: [SettingsView.Pane] = []
    private var forward: [SettingsView.Pane] = []

    init() {
        let stored = UserDefaults.standard.string(forKey: "settingsPane")
        selection = stored.flatMap(SettingsView.Pane.init(rawValue:)) ?? .general
    }

    var visiblePanes: [SettingsView.Pane] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return SettingsView.Pane.allCases }
        return SettingsView.Pane.allCases.filter { "\($0.title) \($0.keywords)".lowercased().contains(q) }
    }

    func select(_ p: SettingsView.Pane) {
        guard p != selection else { return }
        back.append(selection)
        forward.removeAll()
        set(p)
    }

    func goBack() {
        guard let p = back.popLast() else { return }
        forward.append(selection)
        set(p)
    }

    func goForward() {
        guard let p = forward.popLast() else { return }
        back.append(selection)
        set(p)
    }

    private func set(_ p: SettingsView.Pane) {
        selection = p
        canGoBack = !back.isEmpty
        canGoForward = !forward.isEmpty
        UserDefaults.standard.set(p.rawValue, forKey: "settingsPane")
    }
}

/// Sidebar: search field, account row, colored icon tiles (System Settings layout).
struct SettingsSidebar: View {
    @EnvironmentObject var core: CoreBridge
    @ObservedObject var nav: SettingsNavigation

    var body: some View {
        VStack(spacing: 0) {
            SearchField(text: $nav.query, prompt: "Search")
                .padding(.horizontal, 10)
                .padding(.bottom, 6)
            List(selection: Binding(get: { nav.selection }, set: { if let p = $0 { nav.select(p) } })) {
                if nav.query.isEmpty, let s = core.snapshot {
                    AccountRow(s: s)
                        .padding(.vertical, 4)
                        .tag(SettingsView.Pane.bitwarden)
                }
                Section {
                    ForEach(nav.visiblePanes) { p in
                        Label {
                            Text(p.title)
                        } icon: {
                            IconTile(symbol: p.symbol, tint: p.tint, size: 22)
                        }
                        .tag(p)
                    }
                }
            }
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)
        }
    }
}

/// The selected pane.
struct SettingsDetail: View {
    @EnvironmentObject var core: CoreBridge
    @ObservedObject var nav: SettingsNavigation
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        if let s = core.snapshot {
            Group {
                switch nav.selection {
                case .general: GeneralPane(s: s)
                case .bitwarden: BitwardenPane(s: s)
                case .browser: BrowserPane(s: s)
                case .ssh: SSHPane(s: s)
                case .security: SecurityPane(s: s)
                }
            }
            .formStyle(.grouped)
            // Window background behind the grouped cards, as in System Settings, so the
            // toolbar band and the content are one surface.
            .scrollContentBackground(.hidden)
            .modifier(SystemSettingsChrome())
            // Pane switches cross-fade like System Settings (instant with Reduce Motion).
            .id(nav.selection)
            .transition(.opacity)
            .animation(reduceMotion ? nil : .easeInOut(duration: 0.18), value: nav.selection)
        } else {
            ContentUnavailableView(
                core.startError == nil ? "Starting\u{2026}" : "Core not running",
                systemImage: "exclamationmark.shield",
                description: core.startError.map(Text.init)
            )
        }
    }
}

/// Native `NSSearchField` (capsule, Liquid Glass on macOS 26+), as in System Settings.
struct SearchField: NSViewRepresentable {
    @Binding var text: String
    let prompt: String

    func makeNSView(context: Context) -> NSSearchField {
        let f = NSSearchField()
        f.placeholderString = prompt
        f.delegate = context.coordinator
        f.controlSize = .large
        f.sendsSearchStringImmediately = true
        return f
    }

    func updateNSView(_ f: NSSearchField, context: Context) {
        if f.stringValue != text { f.stringValue = text }
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    final class Coordinator: NSObject, NSSearchFieldDelegate {
        var text: Binding<String>
        init(text: Binding<String>) { self.text = text }
        func controlTextDidChange(_ n: Notification) {
            if let f = n.object as? NSSearchField { text.wrappedValue = f.stringValue }
        }
    }
}

/// Content scrolls under the toolbar with the soft (blurred) edge effect, as in System Settings.
private struct SystemSettingsChrome: ViewModifier {
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content.scrollEdgeEffectStyle(.soft, for: .top)
        } else {
            content
        }
    }
}

/// Rounded-square colored icon, as used in System Settings.
struct IconTile: View {
    let symbol: String
    let tint: Color
    var size: CGFloat = 22

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
            .fill(tint.gradient)
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: symbol)
                    .font(.system(size: size * 0.56, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .accessibilityHidden(true)
    }
}

/// Account row at the top of the sidebar (like the Apple Account row).
private struct AccountRow: View {
    let s: Snapshot

    var body: some View {
        HStack(spacing: 10) {
            ZStack {
                Circle().fill(Color.secondary.opacity(0.25))
                Text(initials).font(.system(size: 15, weight: .semibold))
            }
            .frame(width: 36, height: 36)
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(s.account.loggedIn ? (s.account.email ?? "Bitwarden") : "Log In")
                    .font(.headline)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(s.account.loggedIn ? "Bitwarden Account" : "Not connected")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var initials: String {
        guard s.account.loggedIn, let c = s.account.email?.first else { return "?" }
        return String(c).uppercased()
    }
}

/// Header card at the top of each pane (icon, title, one-line summary), as in System Settings.
struct PaneHeader: View {
    let pane: SettingsView.Pane

    var body: some View {
        Section {
            VStack(spacing: 8) {
                IconTile(symbol: pane.symbol, tint: pane.tint, size: 56)
                Text(pane.title).font(.title2.weight(.semibold))
                Text(pane.summary)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .accessibilityElement(children: .combine)
        }
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

/// Validation error from the core, shown at the end of a form.
private struct ErrorSection: View {
    @ObservedObject var editor: SettingsEditor
    var body: some View {
        if let e = editor.error {
            Section {
                Label(e, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
            }
        }
    }
}

/// Secondary explanation under a control.
private struct Note: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(.callout)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.leading)
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
    }
}

private struct StatusValue: View {
    let text: String
    let ok: Bool
    var body: some View {
        HStack(spacing: 6) {
            StatusDot(ok: ok)
            Text(text)
        }
    }
}

// MARK: General

private struct GeneralPane: View {
    let s: Snapshot
    @StateObject private var editor = SettingsEditor()
    @AppStorage("showMenuBarIcon") private var showIcon = true
    @State private var loginItemNote: String?

    var body: some View {
        Form {
            PaneHeader(pane: .general)
            Section {
                Toggle("Launch at login", isOn: Binding(
                    get: { s.settings.launchAtLogin },
                    set: { v in
                        do {
                            try LoginItem.set(v)
                            loginItemNote = LoginItem.requiresApproval
                                ? "Approve WardenFuse in System Settings \u{2192} General \u{2192} Login Items." : nil
                            editor.apply { $0.launchAtLogin = LoginItem.isEnabled || LoginItem.requiresApproval }
                        } catch {
                            loginItemNote = error.localizedDescription
                        }
                    }))
                if let n = loginItemNote { Note(n) }
                Toggle("Show menu bar icon", isOn: Binding(
                    get: { showIcon },
                    set: { v in showIcon = v; editor.apply { $0.showMenuBarIcon = v } }))
                if !showIcon {
                    Note("Open WardenFuse again from Finder or Spotlight to show Settings.")
                }
            }
            Section("Status") {
                LabeledContent("Core") { StatusValue(text: CoreBridge.shared.started ? "Running" : "Stopped", ok: CoreBridge.shared.started) }
                LabeledContent("SSH agent") { StatusValue(text: s.ssh.running ? "Listening" : "Stopped", ok: s.ssh.running) }
                LabeledContent("Browser bridge") {
                    StatusValue(text: s.browser.bridgeRunning ? "Ready \u{00b7} \(s.browser.connections) connected" : "Off",
                                ok: s.browser.bridgeRunning)
                }
                Note("WardenFuse is one menu bar app. The SSH agent and browser unlock keep working when no window is open; quitting WardenFuse stops them.")
            }
            ErrorSection(editor: editor)
        }
    }
}

// MARK: Bitwarden

private struct BitwardenPane: View {
    let s: Snapshot
    @StateObject private var editor = SettingsEditor()
    @State private var confirmLogout = false

    var body: some View {
        Form {
            PaneHeader(pane: .bitwarden)
            Section("Account") {
                if s.account.loggedIn {
                    LabeledContent("Email", value: s.account.email ?? "\u{2014}")
                    LabeledContent("Server URL", value: s.account.serverUrl)
                    if s.account.sessionExpired {
                        Label("The session expired. Log in again to resume sync.", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    HStack {
                        Spacer()
                        Button("Log In Again\u{2026}") { WindowManager.shared.showLogin() }
                        Button("Log Out\u{2026}", role: .destructive) { confirmLogout = true }
                    }
                } else {
                    LabeledContent("Server URL", value: s.settings.serverUrl)
                    LabeledContent("Status") {
                        Button("Log In\u{2026}") { WindowManager.shared.showLogin() }
                    }
                }
            }
            Section("Sync") {
                Toggle("Automatic sync", isOn: editor.binding(s.settings, \.autoSync))
                Picker("Fallback interval", selection: editor.binding(s.settings, \.fallbackSyncIntervalSecs)) {
                    Text("1 minute").tag(UInt64(60))
                    Text("5 minutes").tag(UInt64(300))
                    Text("15 minutes").tag(UInt64(900))
                    Text("1 hour").tag(UInt64(3600))
                }
                Picker("Stop using cached keys after", selection: editor.binding(s.settings, \.maxOfflineHours)) {
                    Text("24 hours offline").tag(UInt64(24))
                    Text("3 days offline").tag(UInt64(72))
                    Text("7 days offline").tag(UInt64(168))
                    Text("30 days offline").tag(UInt64(720))
                }
                LabeledContent("Last successful sync") {
                    if let t = s.sync.lastSuccessUnix {
                        Text(Date(timeIntervalSince1970: TimeInterval(t)), format: .relative(presentation: .named))
                    } else { Text("Never") }
                }
                LabeledContent("Status") {
                    if s.sync.syncing {
                        HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Syncing\u{2026}") }
                    } else if let e = s.sync.error {
                        Text(e).foregroundStyle(.orange).lineLimit(3)
                    } else {
                        Text(s.sync.notificationsConnected ? "Live updates connected" : "Periodic sync")
                    }
                }
                HStack {
                    Note("Live push updates are used when available; the interval applies only while they are unavailable.")
                    Spacer()
                    Button("Sync Now") { Task { await CoreBridge.shared.command("sync_now") } }
                        .disabled(!s.account.loggedIn || s.sync.syncing)
                }
            }
            ErrorSection(editor: editor)
        }
        .confirmationDialog("Log out of Bitwarden?", isPresented: $confirmLogout) {
            Button("Log Out", role: .destructive) { Task { await CoreBridge.shared.command("logout") } }
        } message: {
            Text("The vault key, session and cached SSH keys are removed from this Mac. SSH keys and browser unlock stop working until you log in again.")
        }
    }
}

// MARK: Browser

private struct BrowserPane: View {
    let s: Snapshot
    @StateObject private var editor = SettingsEditor()
    @State private var replaceTarget: Snapshot.Manifest?
    @State private var message: String?

    var body: some View {
        Form {
            PaneHeader(pane: .browser)
            Section {
                Toggle("Browser biometric unlock", isOn: editor.binding(s.settings, \.browserUnlockEnabled))
                LabeledContent("Status") {
                    StatusValue(text: !s.browser.enabled ? "Off" : s.browser.bridgeRunning ? "Ready" : (s.browser.error ?? "Not running"),
                                ok: s.browser.enabled && s.browser.bridgeRunning)
                }
                Note("In the official Bitwarden extension: Settings \u{2192} Account security \u{2192} Unlock with biometrics. Every unlock asks for Touch ID or your password and is independent of the SSH authorization time.")
            }
            Section("Native Messaging") {
                let found = s.browser.manifests.filter { $0.state != "browser_not_found" }
                if found.isEmpty {
                    Note("No supported Chromium browser found (Chrome, Brave, Edge, Chromium, Vivaldi).")
                }
                ForEach(found) { m in
                    LabeledContent {
                        switch m.state {
                        case "installed":
                            Button("Remove") { run("uninstall_browser", ["browser": m.browser.id]) }
                        case "foreign":
                            Button("Use WardenFuse\u{2026}") { replaceTarget = m }
                        default:
                            Button(m.state == "stale" ? "Repair" : "Install") {
                                run("install_browser", ["browser": m.browser.id])
                            }
                        }
                    } label: {
                        Text(m.browser.name)
                        Text(stateText(m))
                    }
                }
            }
            Section("Diagnostics") {
                LabeledContent("Host executable") {
                    Text(s.browser.nmhPath).font(.callout.monospaced()).textSelection(.enabled).lineLimit(2).truncationMode(.middle)
                }
                LabeledContent("Connected browsers", value: "\(s.browser.connections)")
                if let message { Note(message) }
            }
            ErrorSection(editor: editor)
        }
        .confirmationDialog("Replace the existing Bitwarden connection?", isPresented: Binding(
            get: { replaceTarget != nil }, set: { if !$0 { replaceTarget = nil } }), presenting: replaceTarget) { m in
            Button("Use WardenFuse for \(m.browser.name)") {
                run("install_browser", ["browser": m.browser.id, "replace": true])
            }
        } message: { m in
            Text("\(m.browser.name) is connected to another app (\(m.path ?? "unknown")), usually Bitwarden Desktop. WardenFuse keeps a backup and restores it when you remove WardenFuse\u{2019}s connection.")
        }
    }

    private func stateText(_ m: Snapshot.Manifest) -> String {
        switch m.state {
        case "installed": "Connected to WardenFuse"
        case "not_installed": "Not set up"
        case "stale": "Points to another copy of WardenFuse"
        case "foreign": "Used by another app (Bitwarden Desktop?)"
        case "invalid": "Invalid manifest"
        default: m.state
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

private struct SSHPane: View {
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
            PaneHeader(pane: .ssh)
            Section {
                Toggle("Enable SSH agent", isOn: editor.binding(s.settings, \.sshAgentEnabled))
                LabeledContent("Socket path") {
                    HStack {
                        TextField("Socket path", text: $socketDraft)
                            .labelsHidden()
                            .font(.callout.monospaced())
                            .onSubmit { editor.apply { $0.sshSocketPath = socketDraft } }
                        Button { copy(s.ssh.socket) } label: { Image(systemName: "doc.on.doc") }
                            .buttonStyle(.borderless)
                            .help("Copy path")
                            .accessibilityLabel("Copy socket path")
                    }
                }
            }
            Section("Keys") {
                LabeledContent("In agent", value: "\(s.ssh.keys.count) of \(s.ssh.vaultKeyCount) in vault")
                ForEach(s.ssh.keys) { k in
                    LabeledContent {
                        Button { copy(k.publicKey) } label: { Image(systemName: "doc.on.doc") }
                            .buttonStyle(.borderless)
                            .help("Copy public key")
                            .accessibilityLabel("Copy public key of \(k.name)")
                    } label: {
                        Label(k.name, systemImage: k.unlocked ? "key.fill" : "key")
                    }
                }
            }
            Section {
                Picker("Authentication TTL", selection: Binding(
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
                LabeledContent("Custom TTL") {
                    HStack {
                        TextField("Seconds", text: $customTTL)
                            .labelsHidden()
                            .frame(width: 90)
                            .onSubmit(setCustom)
                        Button("Set", action: setCustom).disabled(UInt64(customTTL) == nil)
                    }
                }
                Picker("Authentication scope", selection: editor.binding(s.settings, \.sshScopeMode)) {
                    Text("Per key and requesting app").tag("key_and_process")
                    Text("Per key").tag("key")
                }
                Toggle("List public keys while locked", isOn: editor.binding(s.settings, \.listKeysWhenLocked))
                Toggle("Allow agent forwarding", isOn: editor.binding(s.settings, \.allowAgentForwarding))
            } header: {
                Text("Authentication")
            } footer: {
                Note("The time starts when you authenticate and is never extended by signing. Changing these settings revokes current authorizations.")
            }
            Section("SSH Configuration") {
                Text(snippet).font(.callout.monospaced()).textSelection(.enabled)
                HStack {
                    Button("Copy") { copy(snippet) }
                    Spacer()
                    if s.ssh.sshConfigInstalled {
                        Button("Remove from ~/.ssh/config") { run("uninstall_ssh_config") }
                    } else {
                        Button("Add to ~/.ssh/config\u{2026}") { confirmConfig = true }
                    }
                }
                DisclosureGroup("Git commit signing") {
                    Text(gitSnippet).font(.callout.monospaced()).textSelection(.enabled)
                    Button("Copy") { copy(gitSnippet) }
                }
                if let message { Note(message) }
            }
            ErrorSection(editor: editor)
        }
        .onAppear { socketDraft = s.settings.sshSocketPath; loadSnippet() }
        .onChange(of: s.settings.sshSocketPath) { _, v in socketDraft = v; loadSnippet() }
        .confirmationDialog("Add WardenFuse to ~/.ssh/config?", isPresented: $confirmConfig) {
            Button("Add") { run("install_ssh_config") }
        } message: {
            Text("A clearly marked \u{201c}Host * / IdentityAgent\u{201d} block is added at the top. A backup of the current file is kept and existing entries are not changed.")
        }
    }

    private func setCustom() {
        guard let v = UInt64(customTTL) else { return }
        editor.apply { $0.sshTtlSecs = v; $0.sshApprovalPolicy = v == 0 ? "every_time" : "cache_for_ttl" }
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

private struct SecurityPane: View {
    let s: Snapshot
    @StateObject private var editor = SettingsEditor()
    @State private var confirmReset = false
    @State private var confirmUninstall = false

    private var strongKeychain: Bool { s.security.keychainMode == "secure_access_control" }

    var body: some View {
        Form {
            PaneHeader(pane: .security)
            Section {
                Picker("Authentication", selection: Binding(
                    get: { s.settings.allowPasswordFallback },
                    set: { v in editor.apply { $0.preferTouchId = true; $0.allowPasswordFallback = v } })) {
                    Text("Touch ID or macOS password").tag(true)
                    Text("Touch ID only").tag(false)
                }
                LabeledContent("Touch ID") {
                    StatusValue(text: biometryText, ok: s.security.biometry == "available")
                }
                if !s.settings.allowPasswordFallback && s.security.biometry != "available" {
                    Label("Touch ID is unavailable, so every request will be denied until it is available again or password fallback is allowed.",
                          systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            } header: {
                Text("Touch ID & Password")
            } footer: {
                Note("WardenFuse uses the macOS authentication dialog only and never asks for your password itself. macOS has no password-only mode for apps: when Touch ID is available, the system dialog always offers it first.")
            }
            Section {
                LabeledContent("Keychain protection") {
                    if strongKeychain {
                        Label("Access control (user presence)", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                    } else {
                        Label("Reduced (login keychain)", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                }
                Note(strongKeychain
                     ? "Your Bitwarden key can only be read by macOS after Touch ID or your password succeeds."
                     : "This build is not signed with an Apple Team ID, so macOS does not allow access-controlled Keychain items. WardenFuse reads the key only after authentication succeeds, but macOS does not enforce it. Use a Team-ID signed build for full protection.")
            } header: {
                Text("Keychain")
            }
            Section("Lock the SSH Agent") {
                Toggle("When the Mac sleeps", isOn: editor.binding(s.settings, \.lockOnSleep))
                Toggle("When the screen locks", isOn: editor.binding(s.settings, \.lockOnScreenLock))
                Toggle("When switching users", isOn: editor.binding(s.settings, \.lockOnUserSwitch))
                LabeledContent("On account switch") { Text("Always cleared") }
            }
            Section("Maintenance") {
                LabeledContent {
                    Button("Reset\u{2026}") { confirmReset = true }
                } label: {
                    Text("Reset authentication")
                    Text("Discards all SSH authorizations and decrypted keys.")
                }
                LabeledContent {
                    Button("Remove\u{2026}", role: .destructive) { confirmUninstall = true }
                } label: {
                    Text("Remove WardenFuse data")
                    Text("For uninstalling. Other apps are not touched.")
                }
            }
            ErrorSection(editor: editor)
        }
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
            Text("Logs out, deletes WardenFuse\u{2019}s Keychain items, cache and settings, removes its browser connections (restoring Bitwarden Desktop\u{2019}s if it was replaced) and its ~/.ssh/config block. Afterwards move WardenFuse.app to the Trash.")
        }
    }

    private var biometryText: String {
        switch s.security.biometry {
        case "available": "Available"
        case "not_enrolled": "No fingerprints enrolled"
        default: "Unavailable"
        }
    }
}

func copy(_ s: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(s, forType: .string)
}
