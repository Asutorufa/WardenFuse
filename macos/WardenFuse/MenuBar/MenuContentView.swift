import AppKit
import SwiftUI

/// Holds SwiftUI's `openSettings` action, captured from the always-present menu bar label, so
/// that AppKit code (e.g. reopening the app from Finder) can open the Settings window.
@MainActor
enum SettingsOpener {
    static var action: OpenSettingsAction?
    static func open() {
        NSApp.activate()
        action?()
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
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        let status = MenuStatus(snapshot: snapshot, started: started)
        Image(nsImage: Self.image(status.symbol))
            .accessibilityLabel("WardenFuse, \(status.title)")
            .onAppear { SettingsOpener.action = openSettings }
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

struct MenuContentView: View {
    @EnvironmentObject var core: CoreBridge
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Header(status: MenuStatus(snapshot: core.snapshot, started: core.started))
                .padding(.horizontal, 14)
                .padding(.top, 12)
                .padding(.bottom, 10)

            if let s = core.snapshot {
                Divider()
                StatusRows(s: s, openLogin: openLogin)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                if let error = s.account.sessionExpired ? "Session expired. Log in again to resume sync." : (s.ssh.error ?? s.sync.error) {
                    ErrorRow(text: error)
                        .padding(.horizontal, 14)
                        .padding(.bottom, 10)
                }
                Divider()
                Actions(s: s, core: core)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
            } else if let e = core.startError {
                ErrorRow(text: e).padding(14)
            }

            Divider()
            VStack(spacing: 0) {
                MenuRow(title: "Settings\u{2026}", symbol: "gearshape", shortcut: ",") {
                    NSApp.activate()
                    openSettings()
                }
                MenuRow(title: "Quit WardenFuse", symbol: "power", shortcut: "q") {
                    NSApp.terminate(nil)
                }
            }
            .padding(5)
        }
        .frame(width: 300)
    }

    private func openLogin() {
        NSApp.activate()
        openWindow(id: "login")
    }
}

private struct Header: View {
    let status: MenuStatus

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: status.symbol)
                .font(.title2)
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(status.level == .error ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text("WardenFuse").font(.headline)
                Text(status.title)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }
}

private struct StatusRows: View {
    let s: Snapshot
    let openLogin: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if s.account.loggedIn {
                LabeledContent("Account") {
                    Text(s.account.email ?? "\u{2014}").lineLimit(1).truncationMode(.middle)
                }
                LabeledContent("Server", value: host(s.account.serverUrl))
            } else {
                LabeledContent("Account") {
                    Button("Log In\u{2026}", action: openLogin)
                        .buttonStyle(.link)
                }
            }
            LabeledContent("SSH agent") {
                Text(agentText).foregroundStyle(.secondary)
            }
            if !s.ssh.locked, let until = s.ssh.unlockedUntilUnix, until > Int64(Date().timeIntervalSince1970) {
                LabeledContent("Authorized for") {
                    // Updated by the system text renderer; no app timer.
                    Text(timerInterval: Date()...Date(timeIntervalSince1970: TimeInterval(until)), countsDown: true)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
            }
            LabeledContent("Last sync") {
                Group {
                    if s.sync.syncing {
                        HStack(spacing: 4) { ProgressView().controlSize(.mini); Text("Syncing\u{2026}") }
                    } else if let t = s.sync.lastSuccessUnix {
                        Text(Date(timeIntervalSince1970: TimeInterval(t)), format: .relative(presentation: .named))
                    } else {
                        Text("Never")
                    }
                }
                .foregroundStyle(.secondary)
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
        .font(.callout)
    }

    private var agentText: String {
        if !s.ssh.enabled { return "Off" }
        if !s.ssh.running { return "Not running" }
        if !s.account.loggedIn || !s.ssh.usable { return "Unavailable" }
        let keys = "\(s.ssh.keys.count) key\(s.ssh.keys.count == 1 ? "" : "s")"
        return "\(s.ssh.locked ? "Locked" : "Unlocked") \u{00b7} \(keys)"
    }

    private func host(_ url: String) -> String { URL(string: url)?.host ?? url }
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

private struct Actions: View {
    let s: Snapshot
    let core: CoreBridge

    var body: some View {
        GlassGroup {
            HStack(spacing: 8) {
                if s.ssh.locked {
                    Button {
                        Task { await core.command("unlock_agent") }
                    } label: {
                        Label("Unlock Agent", systemImage: "lock.open").frame(maxWidth: .infinity)
                    }
                    .glassButtonStyle(prominent: true)
                    .disabled(!s.account.loggedIn || !s.ssh.usable)
                } else {
                    Button {
                        Task { await core.command("lock_agent") }
                    } label: {
                        Label("Lock Agent", systemImage: "lock").frame(maxWidth: .infinity)
                    }
                    .glassButtonStyle()
                }
                Button {
                    Task { await core.command("sync_now") }
                } label: {
                    Label("Sync Now", systemImage: "arrow.clockwise").frame(maxWidth: .infinity)
                }
                .glassButtonStyle()
                .disabled(!s.account.loggedIn || s.sync.syncing)
            }
            .controlSize(.large)
        }
    }
}

/// A row that behaves like a native menu item: full-width hit target, accent highlight on
/// hover, trailing key equivalent.
private struct MenuRow: View {
    let title: String
    let symbol: String
    let shortcut: Character
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: symbol).frame(width: 18)
                Text(title)
                Spacer()
                Text("\u{2318}\(String(shortcut).uppercased())")
                    .foregroundStyle(hovering ? AnyShapeStyle(.white.opacity(0.85)) : AnyShapeStyle(.tertiary))
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .contentShape(Rectangle())
            .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
            .background {
                // Concentric with the menu window's corner radius.
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(hovering ? AnyShapeStyle(.tint) : AnyShapeStyle(.clear))
            }
        }
        .buttonStyle(.plain)
        .keyboardShortcut(KeyEquivalent(shortcut), modifiers: .command)
        .onHover { hovering = $0 }
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
