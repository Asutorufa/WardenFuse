import AppKit
import SwiftUI
import Testing
@testable import WardenFuse

/// Renders the real menu and settings views offscreen to PNG files for visual review, in Light
/// and Dark appearance. Opt-in: `WF_RENDER_DIR=/path swift test --filter RenderPreviews`.
@MainActor
struct RenderPreviews {
    static var snapshotJSON: String {
        let now = Int(Date().timeIntervalSince1970)
        return """
        {"account":{"logged_in":true,"email":"rufa@example.com","user_id":"u1","server_url":"https://vaultwarden.example.com","session_expired":false},
         "login":{"stage":"idle","methods":[],"unsupported":[],"error":null},
         "sync":{"syncing":false,"last_success_unix":\(now - 120),"error":null,"notifications_connected":true},
         "ssh":{"enabled":true,"running":true,"usable":true,"socket":"/Users/rufa/.wardenfuse/ssh-agent.sock","vault_key_count":2,
                "keys":[{"name":"GitHub","public_key":"ssh-ed25519 AAAA1","unlocked":true},{"name":"Personal","public_key":"ssh-ed25519 AAAA2","unlocked":false}],
                "list_complete":true,"pending_keys":0,"undecryptable_keys":0,"locked":false,"active_grants":1,
                "unlocked_until_unix":\(now + 412),"last_lock_reason":null,"error":null,"ssh_config_installed":true},
         "browser":{"enabled":true,"bridge_running":true,"connections":2,"error":null,
                    "manifests":[{"browser":{"id":"chrome","name":"Google Chrome","support_dir":"x"},"manifest_path":"/x","state":"installed","has_backup":false},
                                 {"browser":{"id":"brave","name":"Brave","support_dir":"y"},"manifest_path":"/y","state":"installed","has_backup":false}],
                    "nmh_path":"/Applications/WardenFuse.app/Contents/MacOS/wardenfuse-nmh"},
         "security":{"biometry":"available","keychain_mode":"login_keychain_fallback"},
         "settings":{"launch_at_login":true,"show_menu_bar_icon":true,"server_url":"https://vaultwarden.example.com","auto_sync":true,
                     "fallback_sync_interval_secs":300,"max_offline_hours":72,"browser_unlock_enabled":true,"ssh_agent_enabled":true,
                     "ssh_socket_path":"/Users/rufa/.wardenfuse/ssh-agent.sock","ssh_ttl_secs":600,"ssh_approval_policy":"cache_for_ttl",
                     "ssh_scope_mode":"key_and_process","allow_agent_forwarding":false,"list_keys_when_locked":true,"prefer_touch_id":true,
                     "allow_password_fallback":true,"lock_on_screen_lock":true,"lock_on_sleep":true,"lock_on_user_switch":true,"clear_on_account_switch":true}}
        """
    }

    func render<V: View>(_ view: V, size: CGSize, name: String, dark: Bool, dir: String) {
        let host = NSHostingView(rootView: view.environmentObject(CoreBridge.shared))
        let window = NSWindow(contentRect: CGRect(origin: .zero, size: CGSize(width: size.width, height: max(size.height, 400))),
                              styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        window.contentView = host
        RunLoop.main.run(until: Date().addingTimeInterval(0.5))
        let height = size.height > 0 ? size.height : host.fittingSize.height
        window.setContentSize(CGSize(width: size.width, height: height))
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.5))
        guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return }
        host.cacheDisplay(in: host.bounds, to: rep)
        let url = URL(fileURLWithPath: dir).appendingPathComponent("\(name)-\(dark ? "dark" : "light").png")
        try? rep.representation(using: .png, properties: [:])?.write(to: url)
    }

    @Test func renderPreviews() {
        guard let dir = ProcessInfo.processInfo.environment["WF_RENDER_DIR"] else { return }
        CoreBridge.shared.deliverState(Self.snapshotJSON)
        for dark in [false, true] {
            render(VStack(spacing: 8) { MenuHeaderView(onOpenSettings: {}); AgentInfoView(); AccountInfoView(onLogin: {}) }
                       .frame(width: 300).padding(.vertical, 8).background(.regularMaterial),
                   size: CGSize(width: 300, height: 0), name: "menu", dark: dark, dir: dir)
            for pane in ["general", "ssh", "security"] {
                UserDefaults.standard.set(pane, forKey: "settingsPane")
                render(SettingsDetail(nav: SettingsNavigation()), size: CGSize(width: 600, height: 620),
                       name: "settings-\(pane)", dark: dark, dir: dir)
            }
        }
    }
}
