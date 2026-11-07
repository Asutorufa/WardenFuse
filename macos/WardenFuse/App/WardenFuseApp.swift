import AppKit
import ServiceManagement
import SwiftUI

@main
struct WardenFuseApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    var body: some Scene {
        // The status item, Settings and Login windows are AppKit-managed (see
        // StatusMenuController / WindowManager) so the menu is a real NSMenu. SwiftUI still needs
        // a scene; this one only rebinds ⌘, to the settings window.
        Settings { EmptyView() }
            .commands {
                CommandGroup(replacing: .appSettings) {
                    Button("Settings\u{2026}") { WindowManager.shared.showSettings() }
                        .keyboardShortcut(",", modifiers: .command)
                }
            }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private lazy var events = SystemEvents()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // The app hosts the SSH agent and the browser bridge: it must never be reaped by
        // automatic/sudden termination while it looks "idle" (no windows).
        ProcessInfo.processInfo.disableAutomaticTermination("WardenFuse hosts the SSH agent")
        ProcessInfo.processInfo.disableSuddenTermination()
        Task { @MainActor in
            CoreBridge.shared.start()
            StatusMenuController.shared.start()
            events.start()
            LoginItem.reconcile()
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Closing windows (or the menu bar popover) never stops the SSH agent.
        false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        // Launched again from Finder (e.g. while the icon is hidden): show the icon and Settings.
        UserDefaults.standard.set(true, forKey: "showMenuBarIcon")
        WindowManager.shared.showSettings()
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Stops the SSH agent, sync and browser bridge; removes sockets; drops key material.
        MainActor.assumeIsolated { CoreBridge.shared.shutdown() }
    }
}

/// `SMAppService.mainApp`: registers the app itself as a login item (no LaunchAgent plist).
enum LoginItem {
    static var isEnabled: Bool { SMAppService.mainApp.status == .enabled }
    static var requiresApproval: Bool { SMAppService.mainApp.status == .requiresApproval }

    static func set(_ enabled: Bool) throws {
        if enabled {
            if SMAppService.mainApp.status != .enabled { try SMAppService.mainApp.register() }
        } else {
            if SMAppService.mainApp.status == .enabled || SMAppService.mainApp.status == .requiresApproval {
                try SMAppService.mainApp.unregister()
            }
        }
    }

    /// The OS is the source of truth (the user can remove login items in System Settings).
    @MainActor
    static func reconcile() {
        Task {
            try? await Task.sleep(for: .milliseconds(300))
            guard var s = CoreBridge.shared.snapshot?.settings else { return }
            if s.launchAtLogin != isEnabled {
                s.launchAtLogin = isEnabled
                _ = await CoreBridge.shared.updateSettings(s)
            }
        }
    }
}
