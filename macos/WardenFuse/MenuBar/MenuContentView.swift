import AppKit
import SwiftUI

/// Holds SwiftUI's `openSettings` action, captured from the always-present menu bar label, so
/// that AppKit code (e.g. reopening the app from Finder) can open the Settings window.
@MainActor
enum SettingsOpener {
    static var action: OpenSettingsAction?
    static func open() {
        NSApp.activate(ignoringOtherApps: true)
        action?()
    }
}

struct MenuBarIcon: View {
    let snapshot: Snapshot?
    let started: Bool
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        Image(systemName: symbol)
            .accessibilityLabel("WardenFuse: \(label)")
            .onAppear { SettingsOpener.action = openSettings }
    }

    private var state: (String, String) {
        guard started, let s = snapshot else { return ("exclamationmark.shield", "error") }
        if !s.account.loggedIn { return ("shield.slash", "not logged in") }
        if s.sync.error != nil || s.ssh.error != nil || s.account.sessionExpired {
            return ("exclamationmark.shield", "error")
        }
        if s.sync.syncing { return ("arrow.triangle.2.circlepath", "syncing") }
        if s.ssh.locked { return ("lock.shield", "agent locked") }
        return ("checkmark.shield", "agent unlocked")
    }

    private var symbol: String { state.0 }
    private var label: String { state.1 }
}

struct MenuContentView: View {
    @EnvironmentObject var core: CoreBridge
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let s = core.snapshot {
                AccountSection(s: s)
                Divider()
                AgentSection(s: s)
                Divider()
                SyncSection(s: s)
                Divider()
                actions(s)
            } else {
                Label(core.startError ?? "Starting…", systemImage: "hourglass")
                    .foregroundStyle(.secondary)
                Button("Quit WardenFuse") { NSApp.terminate(nil) }
            }
        }
        .padding(14)
        .frame(width: 320)
    }

    @ViewBuilder
    private func actions(_ s: Snapshot) -> some View {
        VStack(spacing: 6) {
            HStack {
                if s.ssh.locked {
                    Button {
                        Task { await core.command("unlock_agent") }
                    } label: { Label("Unlock Agent", systemImage: "lock.open") }
                        .disabled(!s.account.loggedIn || !s.ssh.usable)
                } else {
                    Button {
                        Task { await core.command("lock_agent") }
                    } label: { Label("Lock Agent", systemImage: "lock") }
                }
                Spacer()
                Button {
                    Task { await core.command("sync_now") }
                } label: { Label("Sync Now", systemImage: "arrow.clockwise") }
                    .disabled(!s.account.loggedIn || s.sync.syncing)
            }
            HStack {
                Button {
                    NSApp.activate(ignoringOtherApps: true)
                    openSettings()
                } label: { Label("Settings…", systemImage: "gearshape") }
                Spacer()
                Button {
                    NSApp.terminate(nil)
                } label: { Label("Quit", systemImage: "power") }
            }
        }
        .buttonStyle(.borderless)
        .labelStyle(.titleAndIcon)
    }
}

private struct SectionHeader: View {
    let title: String
    var body: some View {
        Text(title.uppercased())
            .font(.caption2.weight(.semibold))
            .foregroundStyle(.secondary)
    }
}

private struct AccountSection: View {
    let s: Snapshot
    @Environment(\.openWindow) private var openWindow
    @EnvironmentObject var core: CoreBridge

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            SectionHeader(title: "Account")
            if s.account.loggedIn {
                HStack {
                    Image(systemName: s.account.sessionExpired ? "person.crop.circle.badge.exclamationmark" : "person.crop.circle")
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 0) {
                        Text(s.account.email ?? "—").lineLimit(1).truncationMode(.middle)
                        Text(URL(string: s.account.serverUrl)?.host ?? s.account.serverUrl)
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                if s.account.sessionExpired {
                    Button("Session expired — Log In Again…") {
                        NSApp.activate(ignoringOtherApps: true)
                        openWindow(id: "login")
                    }
                    .buttonStyle(.link)
                }
            } else {
                HStack {
                    Text("Not logged in").foregroundStyle(.secondary)
                    Spacer()
                    Button("Log In…") {
                        NSApp.activate(ignoringOtherApps: true)
                        openWindow(id: "login")
                    }
                }
            }
        }
    }
}

private struct AgentSection: View {
    let s: Snapshot

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            SectionHeader(title: "SSH Agent")
            HStack {
                StatusDot(ok: s.ssh.running && s.ssh.usable)
                Text(statusText)
                Spacer()
                Text("\(s.ssh.keys.count) key\(s.ssh.keys.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)
            }
            if !s.ssh.locked, let until = s.ssh.unlockedUntilUnix {
                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                    let remaining = max(0, Int(until) - Int(ctx.date.timeIntervalSince1970))
                    Text("Authorized for \(format(remaining))")
                        .font(.caption).foregroundStyle(.secondary)
                        .monospacedDigit()
                }
            }
            if s.ssh.pendingKeys > 0 || !s.ssh.listComplete && s.account.loggedIn {
                Text(s.ssh.pendingKeys > 0 ? "\(s.ssh.pendingKeys) new or changed key(s) appear after the next authentication" : "Key list appears after the first authentication")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let e = s.ssh.error {
                Text(e).font(.caption).foregroundStyle(.orange)
            }
        }
    }

    private var statusText: String {
        if !s.ssh.enabled { return "Disabled" }
        if !s.ssh.running { return "Not running" }
        if !s.account.loggedIn { return "Waiting for login" }
        if !s.ssh.usable { return "Unavailable" }
        return s.ssh.locked ? "Locked" : "Unlocked"
    }

    private func format(_ secs: Int) -> String {
        String(format: "%d:%02d", secs / 60, secs % 60)
    }
}

private struct SyncSection: View {
    let s: Snapshot

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            SectionHeader(title: "Synchronization")
            HStack {
                if s.sync.syncing {
                    ProgressView().controlSize(.small)
                    Text("Syncing…")
                } else if let t = s.sync.lastSuccessUnix {
                    Text("Last sync ")
                        + Text(Date(timeIntervalSince1970: TimeInterval(t)), style: .relative)
                        + Text(" ago")
                } else {
                    Text("Never synced").foregroundStyle(.secondary)
                }
                Spacer()
                if s.account.loggedIn {
                    Image(systemName: s.sync.notificationsConnected ? "bolt.horizontal" : "clock.arrow.circlepath")
                        .foregroundStyle(.secondary)
                        .help(s.sync.notificationsConnected ? "Live updates connected" : "Periodic sync (live updates unavailable)")
                }
            }
            if let e = s.sync.error {
                Text(e).font(.caption).foregroundStyle(.orange).lineLimit(3)
            }
        }
    }
}

struct StatusDot: View {
    let ok: Bool
    var body: some View {
        Circle()
            .fill(ok ? Color.green.opacity(0.75) : Color.secondary.opacity(0.5))
            .frame(width: 7, height: 7)
    }
}
