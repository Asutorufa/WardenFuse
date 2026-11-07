import AppKit
import Combine
import SwiftUI

// MARK: - Status model

/// Derived, display-only status. All decisions are made by the Rust core.
struct MenuStatus {
    enum Level { case ok, locked, idle, busy, error }
    /// Menu bar glyph: the app icon's shield with a cut-out mark.
    enum Glyph: Hashable { case unlocked, locked, off, error }

    let glyph: Glyph
    let title: String
    let level: Level

    init(snapshot s: Snapshot?, started: Bool) {
        guard started, let s else { self.init(.error, "Not running", .error); return }
        if !s.account.loggedIn { self.init(.off, "Not logged in", .idle); return }
        if s.account.sessionExpired { self.init(.error, "Session expired", .error); return }
        if s.ssh.error != nil || s.sync.error != nil { self.init(.error, "Needs attention", .error); return }
        if !s.ssh.enabled { self.init(.off, "Agent off", .idle); return }
        // Syncing changes only the title, not the glyph, so the icon does not flicker.
        let glyph: Glyph = s.ssh.locked ? .locked : .unlocked
        if s.sync.syncing { self.init(glyph, "Syncing", .busy); return }
        self.init(glyph, s.ssh.locked ? "Locked" : "Unlocked", s.ssh.locked ? .locked : .ok)
    }

    private init(_ glyph: Glyph, _ title: String, _ level: Level) {
        self.glyph = glyph
        self.title = title
        self.level = level
    }

    /// Vector template image (tinted by the system like any status item, crisp at every scale).
    @MainActor private static var cache: [Glyph: NSImage] = [:]
    @MainActor static func image(_ glyph: Glyph) -> NSImage {
        if let i = cache[glyph] { return i }
        let img = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { _ in
            StatusGlyph.draw(glyph)
            return true
        }
        img.isTemplate = true
        cache[glyph] = img
        return img
    }
}

/// Draws the menu bar glyph in an 18×18 pt box (shield geometry taken from the app icon).
enum StatusGlyph {
    /// App-icon coordinates (1024 canvas) mapped into the 18 pt box.
    private static let k: CGFloat = 15.6 / 562
    private static func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint {
        NSPoint(x: 9 + (x - 512) * k, y: 1.2 + (y - 228) * k)
    }

    static func shield() -> NSBezierPath {
        let path = NSBezierPath()
        let top: CGFloat = 790, bottom: CGFloat = 228, cx: CGFloat = 512, half: CGFloat = 228
        path.move(to: p(cx, top))
        path.curve(to: p(cx + half, top - 70), controlPoint1: p(cx + 90, top - 40), controlPoint2: p(cx + 170, top - 60))
        path.curve(to: p(cx, bottom), controlPoint1: p(cx + half + 6, 470), controlPoint2: p(cx + 140, 300))
        path.curve(to: p(cx - half, top - 70), controlPoint1: p(cx - 140, 300), controlPoint2: p(cx - half - 6, 470))
        path.curve(to: p(cx, top), controlPoint1: p(cx - 170, top - 60), controlPoint2: p(cx - 90, top - 40))
        path.close()
        return path
    }

    private static func keyhole() -> NSBezierPath {
        let path = NSBezierPath(ovalIn: NSRect(x: 9 - 1.9, y: 9.6, width: 3.8, height: 3.8))
        let stem = NSBezierPath()
        stem.move(to: NSPoint(x: 9 - 0.9, y: 10.2))
        stem.line(to: NSPoint(x: 9 - 1.4, y: 5.4))
        stem.line(to: NSPoint(x: 9 + 1.4, y: 5.4))
        stem.line(to: NSPoint(x: 9 + 0.9, y: 10.2))
        stem.close()
        path.append(stem)
        return path
    }

    private static func padlock() -> NSBezierPath {
        let body = NSBezierPath(roundedRect: NSRect(x: 9 - 2.9, y: 5.2, width: 5.8, height: 4.6), xRadius: 1, yRadius: 1)
        let shackle = NSBezierPath()
        shackle.move(to: NSPoint(x: 9 - 1.8, y: 9.6))
        shackle.line(to: NSPoint(x: 9 - 1.8, y: 11.1))
        shackle.appendArc(withCenter: NSPoint(x: 9, y: 11.1), radius: 1.8, startAngle: 180, endAngle: 0, clockwise: true)
        shackle.line(to: NSPoint(x: 9 + 1.8, y: 9.6))
        let outline = shackle.copy() as! NSBezierPath
        outline.lineWidth = 1.2
        return body.appendingStroke(outline)
    }

    private static func exclamation() -> NSBezierPath {
        let path = NSBezierPath(roundedRect: NSRect(x: 9 - 0.85, y: 8.0, width: 1.7, height: 5.6), xRadius: 0.85, yRadius: 0.85)
        path.append(NSBezierPath(ovalIn: NSRect(x: 9 - 1, y: 4.9, width: 2, height: 2)))
        return path
    }

    static func draw(_ glyph: MenuStatus.Glyph) {
        NSColor.black.setFill()
        NSColor.black.setStroke()
        let shield = shield()
        guard glyph != .off else {
            // Outline only: logged out / agent off.
            let scaled = shield.copy() as! NSBezierPath
            var t = AffineTransform(translationByX: -9, byY: -9)
            t.append(AffineTransform(scale: 0.9))
            t.append(AffineTransform(translationByX: 9, byY: 9))
            scaled.transform(using: t)
            scaled.lineWidth = 1.5
            scaled.lineJoinStyle = .round
            scaled.stroke()
            return
        }
        shield.fill()
        let mark: NSBezierPath = switch glyph {
        case .unlocked: keyhole()
        case .locked: padlock()
        case .error: exclamation()
        case .off: NSBezierPath()
        }
        NSGraphicsContext.current?.compositingOperation = .destinationOut
        mark.fill()
        NSGraphicsContext.current?.compositingOperation = .sourceOver
    }
}

private extension NSBezierPath {
    /// The stroke outline of `other` added as a fillable area (for knock-outs).
    func appendingStroke(_ other: NSBezierPath) -> NSBezierPath {
        let cg = other.cgPath.copy(strokingWithWidth: other.lineWidth, lineCap: .round, lineJoin: .round, miterLimit: 10)
        append(NSBezierPath(cgPath: cg))
        return self
    }
}

// MARK: - Status item + native menu

/// The menu bar item. A real `NSMenu`, so material, corner radius, highlight, keyboard
/// navigation and key equivalents are exactly the system's. Section headers and actions are
/// native menu items; only the information rows are small embedded SwiftUI views.
@MainActor
final class StatusMenuController: NSObject, NSMenuDelegate {
    static let shared = StatusMenuController()

    private var item: NSStatusItem?
    private let menu = NSMenu()
    private var bag = Set<AnyCancellable>()
    private var defaultsObserver: NSObjectProtocol?

    func start() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.behavior = []
        menu.delegate = self
        menu.autoenablesItems = false
        item.menu = menu
        self.item = item
        updateIcon()

        CoreBridge.shared.$snapshot
            .combineLatest(CoreBridge.shared.$started)
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.updateIcon() }
            .store(in: &bag)

        applyVisibility()
        defaultsObserver = NotificationCenter.default.addObserver(
            forName: UserDefaults.didChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.applyVisibility() }
        }
    }

    private func applyVisibility() {
        let visible = UserDefaults.standard.object(forKey: "showMenuBarIcon") as? Bool ?? true
        if item?.isVisible != visible { item?.isVisible = visible }
    }

    private func updateIcon() {
        let status = MenuStatus(snapshot: CoreBridge.shared.snapshot, started: CoreBridge.shared.started)
        item?.button?.image = MenuStatus.image(status.glyph)
        item?.button?.setAccessibilityLabel("WardenFuse, \(status.title)")
    }

    // Built when the menu opens: nothing is kept around while it is closed.
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let core = CoreBridge.shared
        let status = MenuStatus(snapshot: core.snapshot, started: core.started)

        menu.addItem(viewItem(MenuHeaderView(onOpenSettings: { [weak self] in self?.openSettings() })))
        menu.addItem(.separator())

        guard let s = core.snapshot else {
            if let e = core.startError { menu.addItem(viewItem(ErrorRow(text: e).menuRowPadding())) }
            addQuit()
            return
        }

        menu.addItem(.sectionHeader(title: "SSH Agent \u{00b7} \(status.title)"))
        menu.addItem(viewItem(AgentInfoView()))
        menu.addItem(.separator())

        menu.addItem(.sectionHeader(title: "Bitwarden"))
        menu.addItem(viewItem(AccountInfoView(onLogin: { [weak self] in self?.openLogin() })))
        menu.addItem(.separator())

        if s.ssh.locked {
            let i = action("Unlock Agent", #selector(unlockAgent))
            i.isEnabled = s.account.loggedIn && s.ssh.usable
            menu.addItem(i)
        } else {
            menu.addItem(action("Lock Agent", #selector(lockAgent)))
        }
        let sync = action("Sync Now", #selector(syncNow))
        sync.isEnabled = s.account.loggedIn && !s.sync.syncing
        menu.addItem(sync)
        menu.addItem(action("Settings\u{2026}", #selector(openSettingsAction), key: ","))
        addQuit()
    }

    func menuDidClose(_ menu: NSMenu) {
        // Release the embedded SwiftUI views until the next open.
        DispatchQueue.main.async { menu.removeAllItems() }
    }

    private func addQuit() {
        menu.addItem(.separator())
        menu.addItem(action("Quit WardenFuse", #selector(quit), key: "q"))
    }

    private func action(_ title: String, _ sel: Selector, key: String = "") -> NSMenuItem {
        let i = NSMenuItem(title: title, action: sel, keyEquivalent: key)
        i.target = self
        return i
    }

    private func viewItem<V: View>(_ view: V) -> NSMenuItem {
        let host = NSHostingView(rootView: view.environmentObject(CoreBridge.shared).frame(width: 300))
        host.sizingOptions = [.intrinsicContentSize]
        host.frame.size = host.fittingSize
        let i = NSMenuItem()
        i.view = host
        return i
    }

    private func openSettings() {
        menu.cancelTracking()
        WindowManager.shared.showSettings()
    }

    private func openLogin() {
        menu.cancelTracking()
        WindowManager.shared.showLogin()
    }

    @objc private func openSettingsAction() { WindowManager.shared.showSettings() }
    @objc private func unlockAgent() { Task { await CoreBridge.shared.command("unlock_agent") } }
    @objc private func lockAgent() { Task { await CoreBridge.shared.command("lock_agent") } }
    @objc private func syncNow() { Task { await CoreBridge.shared.command("sync_now") } }
    @objc private func quit() { NSApp.terminate(nil) }
}

// MARK: - Embedded rows

private extension View {
    /// Horizontal inset matching native menu item text.
    func menuRowPadding() -> some View {
        padding(.horizontal, 14)
    }
}

struct MenuHeaderView: View {
    let onOpenSettings: () -> Void

    private var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"
    }

    var body: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 1) {
                Text("WardenFuse").font(.headline)
                Text("Version \(version)").font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer()
            PillButton(title: "Open Settings", action: onOpenSettings)
        }
        .menuRowPadding()
        .padding(.vertical, 4)
    }
}

struct AgentInfoView: View {
    @EnvironmentObject var core: CoreBridge

    var body: some View {
        if let s = core.snapshot {
            VStack(alignment: .leading, spacing: 4) {
                InfoRow(title: "Keys") { Text(keysText(s)) }
                if !s.ssh.locked, let until = s.ssh.unlockedUntilUnix,
                   until > Int64(Date().timeIntervalSince1970) {
                    let end = Date(timeIntervalSince1970: TimeInterval(until))
                    InfoRow(title: "Authorized") {
                        // Rendered by the system; no app timer.
                        Text(timerInterval: Date()...end, countsDown: true).monospacedDigit()
                    }
                    ProgressView(timerInterval: Date()...end, countsDown: true) { EmptyView() } currentValueLabel: { EmptyView() }
                        .progressViewStyle(.linear)
                        .accessibilityLabel("Authorization time remaining")
                } else {
                    InfoRow(title: "Authorization") {
                        Text(s.settings.sshApprovalPolicy == "every_time" ? "Every signature" : "Touch ID on next use")
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
                if let e = s.ssh.error {
                    ErrorRow(text: e).padding(.top, 2)
                }
            }
            .menuRowPadding()
            .padding(.vertical, 2)
        }
    }

    private func keysText(_ s: Snapshot) -> String {
        if !s.ssh.enabled { return "Agent off" }
        if !s.ssh.running { return "Not running" }
        if !s.account.loggedIn || !s.ssh.usable { return "Unavailable" }
        let n = s.ssh.listComplete ? s.ssh.keys.count : s.ssh.vaultKeyCount
        return "\(n) in vault"
    }
}

struct AccountInfoView: View {
    @EnvironmentObject var core: CoreBridge
    let onLogin: () -> Void

    var body: some View {
        if let s = core.snapshot {
            VStack(alignment: .leading, spacing: 4) {
                if s.account.loggedIn {
                    InfoRow(title: "Account") { Text(s.account.email ?? "\u{2014}") }
                    InfoRow(title: "Server") { Text(URL(string: s.account.serverUrl)?.host ?? s.account.serverUrl) }
                } else {
                    HStack {
                        Text("Not logged in")
                        Spacer()
                        PillButton(title: "Log In\u{2026}", action: onLogin)
                    }
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
                .accessibilityElement(children: .combine)
                if let e = s.account.sessionExpired ? "Session expired. Log in again to resume sync." : s.sync.error {
                    ErrorRow(text: e).padding(.top, 2)
                }
            }
            .menuRowPadding()
            .padding(.vertical, 2)
        }
    }
}

/// Capsule action (Liquid Glass on macOS 26+).
struct PillButton: View {
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
struct Pill: View {
    let text: String
    var body: some View {
        Text(text)
            .contentTransition(.opacity)
            .font(.subheadline.weight(.medium))
            .padding(.horizontal, 9)
            .padding(.vertical, 3)
            .background(.quaternary, in: Capsule())
    }
}

struct InfoRow<Value: View>: View {
    let title: String
    @ViewBuilder var value: Value
    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title)
            Spacer(minLength: 12)
            value.foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                .contentTransition(.numericText())
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}

struct ErrorRow: View {
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

struct StatusDot: View {
    let ok: Bool
    var body: some View {
        Circle()
            .fill(ok ? Color.green.opacity(0.75) : Color.secondary.opacity(0.5))
            .frame(width: 7, height: 7)
            .accessibilityHidden(true)
    }
}
