import AppKit
import Combine
import SwiftUI

/// Creates the Settings and Login windows on demand and releases them when they close, so no
/// window content stays resident while the app sits in the menu bar.
@MainActor
final class WindowManager: NSObject, NSWindowDelegate {
    static let shared = WindowManager()

    private var settings: SettingsWindowController?
    private var login: NSWindow?

    func showSettings(pane: SettingsView.Pane? = nil) {
        if settings == nil {
            settings = SettingsWindowController()
            settings?.window?.delegate = self
        }
        if let pane { settings?.nav.select(pane) }
        present(settings?.window)
    }

    func showLogin() {
        if login == nil {
            let host = NSHostingController(rootView: LoginView().environmentObject(CoreBridge.shared))
            host.sceneBridgingOptions = [.title]
            let w = NSWindow(contentViewController: host)
            w.styleMask = [.titled, .closable, .resizable]
            w.title = "Log In to Bitwarden"
            w.isReleasedWhenClosed = false
            w.delegate = self
            w.contentMinSize = NSSize(width: 420, height: 360)
            w.center()
            login = w
        }
        present(login)
    }

    func closeLogin() {
        login?.close()
    }

    private func present(_ w: NSWindow?) {
        NSApp.activate()
        w?.makeKeyAndOrderFront(nil)
        // Open without a focused control (no focus ring in the sidebar).
        if w === settings?.window { w?.makeFirstResponder(nil) }
    }

    func windowWillClose(_ notification: Notification) {
        guard let w = notification.object as? NSWindow else { return }
        // Drop the controllers so the SwiftUI view trees are freed.
        DispatchQueue.main.async { [weak self] in
            if w === self?.settings?.window { self?.settings = nil }
            if w === self?.login {
                w.contentViewController = nil
                self?.login = nil
            }
        }
    }
}

/// System Settings–style window built from AppKit split-view primitives:
/// * sidebar `NSSplitViewItem` (full-height sidebar material, no divider line),
/// * content item without a titlebar separator, so content scrolls under the toolbar with the
///   system's soft edge blur instead of a hard line,
/// * unified toolbar with a back/forward group and the pane title.
@MainActor
final class SettingsWindowController: NSWindowController, NSToolbarDelegate {
    let nav = SettingsNavigation()
    private var bag = Set<AnyCancellable>()
    private weak var navGroup: NSToolbarItemGroup?
    private let titleLabel = NSTextField(labelWithString: "")

    private static let navID = NSToolbarItem.Identifier("wf.nav")
    private static let titleID = NSToolbarItem.Identifier("wf.title")

    init() {
        let sidebar = NSHostingController(
            rootView: SettingsSidebar(nav: nav).environmentObject(CoreBridge.shared))
        let detail = NSHostingController(
            rootView: SettingsDetail(nav: nav).environmentObject(CoreBridge.shared))

        let split = NSSplitViewController()
        split.splitView = ClearDividerSplitView()
        split.splitView.isVertical = true
        split.splitView.dividerStyle = .thin
        let sidebarItem = NSSplitViewItem(sidebarWithViewController: sidebar)
        sidebarItem.minimumThickness = 240
        sidebarItem.maximumThickness = 340
        sidebarItem.preferredThicknessFraction = 0.3
        sidebarItem.canCollapse = false
        sidebarItem.titlebarSeparatorStyle = .none
        let contentItem = NSSplitViewItem(viewController: detail)
        contentItem.titlebarSeparatorStyle = .none
        contentItem.minimumThickness = 460
        if #available(macOS 26.0, *) {
            // Content extends under the sidebar and the toolbar (safe-area insets keep it
            // readable): no seam next to the sidebar.
            contentItem.automaticallyAdjustsSafeAreaInsets = true
        }
        split.addSplitViewItem(sidebarItem)
        split.addSplitViewItem(contentItem)

        let w = NSWindow(contentViewController: split)
        w.styleMask = [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView]
        w.title = "WardenFuse Settings"
        w.titleVisibility = .hidden
        w.titlebarSeparatorStyle = .none
        w.toolbarStyle = .unified
        // Keep the standard titlebar: it is what gives the Liquid Glass scroll-edge blur when
        // content scrolls under the toolbar (a transparent titlebar disables it).
        w.isReleasedWhenClosed = false
        w.setContentSize(NSSize(width: 880, height: 660))
        w.contentMinSize = NSSize(width: 740, height: 480)
        w.center()
        w.setFrameAutosaveName("WardenFuseSettingsWindow")
        super.init(window: w)

        let toolbar = NSToolbar(identifier: "wf.settings")
        toolbar.delegate = self
        toolbar.displayMode = .iconOnly
        toolbar.allowsUserCustomization = false
        w.toolbar = toolbar

        titleLabel.font = .systemFont(ofSize: NSFont.systemFontSize + 2, weight: .semibold)
        nav.$selection
            .combineLatest(nav.$canGoBack, nav.$canGoForward)
            .receive(on: RunLoop.main)
            .sink { [weak self] pane, back, forward in
                self?.titleLabel.stringValue = pane.title
                self?.window?.title = pane.title
                self?.navGroup?.subitems.first?.isEnabled = back
                self?.navGroup?.subitems.last?.isEnabled = forward
            }
            .store(in: &bag)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [.sidebarTrackingSeparator, Self.navID, Self.titleID, .flexibleSpace]
    }

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        toolbarDefaultItemIdentifiers(toolbar)
    }

    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier id: NSToolbarItem.Identifier,
                 willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        switch id {
        case Self.navID:
            let images = ["chevron.left", "chevron.right"].compactMap {
                NSImage(systemSymbolName: $0, accessibilityDescription: nil)
            }
            let group = NSToolbarItemGroup(itemIdentifier: id, images: images, selectionMode: .momentary,
                                           labels: ["Back", "Forward"], target: self, action: #selector(navigate(_:)))
            group.controlRepresentation = .expanded
            group.isBordered = true
            group.subitems.first?.isEnabled = nav.canGoBack
            group.subitems.last?.isEnabled = nav.canGoForward
            navGroup = group
            return group
        case Self.titleID:
            let item = NSToolbarItem(itemIdentifier: id)
            item.view = titleLabel
            item.isBordered = false
            return item
        default:
            return nil
        }
    }

    @objc private func navigate(_ sender: NSToolbarItemGroup) {
        if sender.selectedIndex == 0 { nav.goBack() } else { nav.goForward() }
    }
}

/// Split view without a visible divider line between sidebar and content (System Settings
/// draws none; the sidebar material alone separates the columns).
final class ClearDividerSplitView: NSSplitView {
    override var dividerColor: NSColor { .clear }
}
