import AppKit
import SwiftUI

/// Holds SwiftUI's `openWindow` action, captured from the always-present menu bar label, so
/// that AppKit code (e.g. reopening the app from Finder) can open the settings window.
@MainActor
enum SettingsOpener {
    static var action: OpenWindowAction?
    static func open() {
        NSApp.activate()
        action?(id: "settings")
    }
}

// MARK: - Status model

/// Derived, display-only status. All decisions are made by the Rust core.
struct MenuStatus {
    enum Level { case ok, locked, idle, busy, error }
    let symbol: String
    let title: String
    let level: Level

    init(snapshot s: Snapshot?, started: Bool) {
        guard started, let s else {
            self.init("exclamationmark.shield", "Not running", .error); return
        }
        if !s.account.loggedIn { self.init("shield.slash", "Not logged in", .idle); return }
        if s.account.sessionExpired { self.init("exclamationmark.shield", "Session expired", .error); return }
        if s.ssh.error != nil || s.sync.error != nil {
            self.init("exclamationmark.shield", "Needs attention", .error); return
        }
        if s.sync.syncing { self.init("arrow.triangle.2.circlepath", "Syncing", .busy); return }
        if !s.ssh.enabled { self.init("shield", "SSH agent off", .idle); return }
        if s.ssh.locked { self.init("lock.shield", "Agent locked", .locked); return }
        self.init("checkmark.shield", "Agent unlocked", .ok)
    }

    private init(_ symbol: String, _ title: String, _ level: Level) {
        self.symbol = symbol
        self.title = title
        self.level = level
    }
}

// MARK: - Menu bar icon

struct MenuBarIcon: View {
    let snapshot: Snapshot?
    let started: Bool
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let status = MenuStatus(snapshot: snapshot, started: started)
        Image(nsImage: Self.image(status.symbol))
            .accessibilityLabel("WardenFuse, \(status.title)")
            .onAppear { SettingsOpener.action = openWindow }
    }

    /// Template image at a slightly larger point size than the default label rendering, matching
    /// the visual weight of system status items. Cached: the label is re-rendered on state
    /// changes only.
    @MainActor private static var cache: [String: NSImage] = [:]
    static func image(_ name: String) -> NSImage {
        if let i = cache[name] { return i }
        let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .medium)
        let img = NSImage(systemSymbolName: name, accessibilityDescription: nil)?
            .withSymbolConfiguration(config) ?? NSImage()
        img.isTemplate = true
        cache[name] = img
        return img
    }
}

// MARK: - Menu window

/// Menu bar window laid out like a native status menu: app header with a pill action, a small
/// section caption, label/value rows, a countdown bar for the SSH authorization, then plain menu
/// items. The window background is the system's own material; only the header pill uses glass.
struct MenuContentView: View {
    @EnvironmentObject var core: CoreBridge
    @Environment(\.openWindow) private var openWindow

    private var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"
    }

    var body: some View {
        let status = MenuStatus(snapshot: core.snapshot, started: core.started)
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("WardenFuse").font(.headline)
                    Text("Version \(version)").font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
                PillButton(title: "Open Settings") { openSettings() }
            }
            .padding(.horizontal, 14)
            .padding(.top, 12)
            .padding(.bottom, 10)

            MenuDivider()

            if let s = core.snapshot {
                Caption(text: "SSH Agent \u{00b7} \(status.title)")
                AgentSection(s: s)
                    .padding(.horizontal, 14)

                if let error = s.account.sessionExpired
                    ? "Session expired. Log in again to resume sync."
                    : (s.ssh.error ?? s.sync.error) {
                    ErrorRow(text: error)
                        .padding(.horizontal, 14)
                        .padding(.top, 8)
                }

                MenuDivider().padding(.top, 10)

                Caption(text: "Bitwarden")
                AccountSection(s: s, openLogin: openLogin)
                    .padding(.horizontal, 14)
                    .padding(.bottom, 6)

                MenuDivider()

                VStack(spacing: 0) {
                    if s.ssh.locked {
                        MenuRow(title: "Unlock Agent", enabled: s.account.loggedIn && s.ssh.usable) {
                            Task { await core.command("unlock_agent") }
                        }
                    } else {
                        MenuRow(title: "Lock Agent") { Task { await core.command("lock_agent") } }
                    }
                    MenuRow(title: "Sync Now", enabled: s.account.loggedIn && !s.sync.syncing) {
                        Task { await core.command("sync_now") }
                    }
                    MenuRow(title: "Settings\u{2026}", shortcut: ",") { openSettings() }
                }
                .padding(5)
            } else if let e = core.startError {
                ErrorRow(text: e).padding(14)
            }

            MenuDivider()
            MenuRow(title: "Quit WardenFuse", shortcut: "q") { NSApp.terminate(nil) }
                .padding(5)
        }
        .frame(width: 300)
    }

    private func openSettings() {
        NSApp.activate()
        openWindow(id: "settings")
    }

    private func openLogin() {
        NSApp.activate()
        openWindow(id: "login")
    }
}

private struct MenuDivider: View {
    var body: some View {
        Divider().padding(.horizontal, 14)
    }
}

/// Small grey section caption (like a menu section header).
private struct Caption: View {
    let text: String
    var body: some View {
        Text(text)
            .font(.subheadline.weight(.medium))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 14)
            .padding(.top, 10)
            .padding(.bottom, 6)
            .accessibilityAddTraits(.isHeader)
    }
}

/// Capsule action in the header (Liquid Glass on macOS 26+).
private struct PillButton: View {
    let title: String
    let action: () -> Void
    var body: some View {
        Button(title, action: action)
            .font(.subheadline.weight(.medium))
            .buttonBorderShape(.capsule)
            .controlSize(.small)
            .glassButtonStyle()
    }
}

/// Non-interactive status capsule.
private struct Pill: View {
    let text: String
    var body: some View {
        Text(text)
            .font(.subheadline.weight(.medium))
            .padding(.horizontal, 9)
            .padding(.vertical, 3)
            .background(.quaternary, in: Capsule())
    }
}

private struct Row<Value: View>: View {
    let title: String
    @ViewBuilder var value: Value
    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title)
            Spacer(minLength: 12)
            value.foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
        }
        .padding(.vertical, 3)
        .accessibilityElement(children: .combine)
    }
}

private struct AgentSection: View {
    let s: Snapshot

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Row(title: "Keys") { Text(keysText) }
            if !s.ssh.locked, let until = s.ssh.unlockedUntilUnix,
               until > Int64(Date().timeIntervalSince1970) {
                let end = Date(timeIntervalSince1970: TimeInterval(until))
                Row(title: "Authorized") {
                    // Rendered by the system; no app timer.
                    Text(timerInterval: Date()...end, countsDown: true).monospacedDigit()
                }
                ProgressView(timerInterval: Date()...end, countsDown: true) { EmptyView() } currentValueLabel: { EmptyView() }
                    .progressViewStyle(.linear)
                    .tint(.accentColor)
                    .padding(.bottom, 4)
                    .accessibilityLabel("Authorization time remaining")
            } else {
                Row(title: "Authorization") {
                    Text(s.settings.sshApprovalPolicy == "every_time" ? "Every signature"
                         : "Touch ID on next use")
                }
            }
            if s.ssh.pendingKeys > 0 || (s.account.loggedIn && !s.ssh.listComplete) {
                Text(s.ssh.pendingKeys > 0
                     ? "\(s.ssh.pendingKeys) new or changed key(s) appear after the next authentication."
                     : "Key names appear after the first authentication.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var keysText: String {
        if !s.ssh.enabled { return "Agent off" }
        if !s.ssh.running { return "Not running" }
        if !s.account.loggedIn || !s.ssh.usable { return "Unavailable" }
        let n = s.ssh.listComplete ? s.ssh.keys.count : s.ssh.vaultKeyCount
        return "\(n) in vault"
    }
}

private struct AccountSection: View {
    let s: Snapshot
    let openLogin: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if s.account.loggedIn {
                Row(title: "Account") { Text(s.account.email ?? "\u{2014}") }
                Row(title: "Server") { Text(URL(string: s.account.serverUrl)?.host ?? s.account.serverUrl) }
            } else {
                HStack {
                    Text("Not logged in")
                    Spacer()
                    PillButton(title: "Log In\u{2026}", action: openLogin)
                }
                .padding(.vertical, 3)
            }
            HStack(alignment: .firstTextBaseline) {
                Text("Sync")
                Spacer(minLength: 12)
                if s.sync.syncing {
                    Pill(text: "Syncing\u{2026}")
                } else if let t = s.sync.lastSuccessUnix {
                    Pill(text: "Updated \(Date(timeIntervalSince1970: TimeInterval(t)).formatted(.relative(presentation: .named)))")
                } else {
                    Pill(text: "Never synced")
                }
            }
            .padding(.vertical, 3)
            .accessibilityElement(children: .combine)
        }
    }
}

private struct ErrorRow: View {
    let text: String
    var body: some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
        }
        .font(.callout)
        .accessibilityLabel("Error: \(text)")
    }
}

/// A row that behaves like a native menu item: full-width hit target, accent highlight on
/// hover, optional trailing key equivalent.
private struct MenuRow: View {
    let title: String
    var shortcut: Character?
    var enabled = true
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack {
                Text(title)
                Spacer()
                if let shortcut {
                    Text("\u{2318}\(String(shortcut).uppercased())")
                        .foregroundStyle(hovering ? AnyShapeStyle(.white.opacity(0.85)) : AnyShapeStyle(.tertiary))
                }
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .contentShape(Rectangle())
            .foregroundStyle(hovering && enabled ? AnyShapeStyle(.white) : AnyShapeStyle(enabled ? .primary : .tertiary))
            .background {
                // Concentric with the menu window's corner radius.
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(hovering && enabled ? AnyShapeStyle(.tint) : AnyShapeStyle(.clear))
            }
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .modifier(ShortcutModifier(shortcut: shortcut))
        .onHover { hovering = $0 }
    }
}

private struct ShortcutModifier: ViewModifier {
    let shortcut: Character?
    func body(content: Content) -> some View {
        if let shortcut {
            content.keyboardShortcut(KeyEquivalent(shortcut), modifiers: .command)
        } else {
            content
        }
    }
}

struct StatusDot: View {
    let ok: Bool
    var body: some View {
        Circle()
            .fill(ok ? Color.green.opacity(0.75) : Color.secondary.opacity(0.5))
            .frame(width: 7, height: 7)
            .accessibilityHidden(true)
    }
}
