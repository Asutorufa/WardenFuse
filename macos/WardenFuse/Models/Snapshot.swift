import Foundation

/// Mirror of `Settings` in crates/wardenfuse-core/src/config.rs (snake_case on the wire).
struct CoreSettings: Codable, Equatable {
    var launchAtLogin: Bool
    var showMenuBarIcon: Bool
    var serverUrl: String
    var autoSync: Bool
    var fallbackSyncIntervalSecs: UInt64
    var maxOfflineHours: UInt64
    var browserUnlockEnabled: Bool
    var sshAgentEnabled: Bool
    var sshSocketPath: String
    var sshTtlSecs: UInt64
    var sshApprovalPolicy: String   // "every_time" | "cache_for_ttl"
    var sshScopeMode: String        // "key_and_process" | "key"
    var allowAgentForwarding: Bool
    var listKeysWhenLocked: Bool
    var preferTouchId: Bool
    var allowPasswordFallback: Bool
    var lockOnScreenLock: Bool
    var lockOnSleep: Bool
    var lockOnUserSwitch: Bool
    var clearOnAccountSwitch: Bool
}

struct Snapshot: Decodable, Equatable {
    struct Account: Decodable, Equatable {
        var loggedIn: Bool
        var email: String?
        var userId: String?
        var serverUrl: String
        var sessionExpired: Bool
    }
    struct Login: Decodable, Equatable {
        var stage: String
        var methods: [String]
        var unsupported: [String]
        var error: String?
    }
    struct Sync: Decodable, Equatable {
        var syncing: Bool
        var lastSuccessUnix: Int64?
        var error: String?
        var notificationsConnected: Bool
    }
    struct Key: Decodable, Equatable, Identifiable {
        var name: String
        var publicKey: String
        var unlocked: Bool
        var id: String { publicKey }
    }
    struct Ssh: Decodable, Equatable {
        var enabled: Bool
        var running: Bool
        var usable: Bool
        var socket: String
        var vaultKeyCount: Int
        var keys: [Key]
        var listComplete: Bool
        var pendingKeys: Int
        var undecryptableKeys: Int
        var locked: Bool
        var activeGrants: Int
        var unlockedUntilUnix: Int64?
        var lastLockReason: String?
        var error: String?
        var sshConfigInstalled: Bool
    }
    struct BrowserInfo: Decodable, Equatable {
        var id: String
        var name: String
    }
    struct Manifest: Decodable, Equatable, Identifiable {
        var browser: BrowserInfo
        var manifestPath: String
        var state: String
        var path: String?
        var hasBackup: Bool
        var id: String { browser.id }
    }
    struct Browser: Decodable, Equatable {
        var enabled: Bool
        var bridgeRunning: Bool
        var connections: Int
        var error: String?
        var manifests: [Manifest]
        var nmhPath: String
    }
    struct Security: Decodable, Equatable {
        var biometry: String
        var keychainMode: String
    }

    var account: Account
    var login: Login
    var sync: Sync
    var ssh: Ssh
    var browser: Browser
    var security: Security
    var settings: CoreSettings
}

/// Authentication request from the core (crates/wardenfuse-core/src/platform.rs).
struct AuthRequestPayload: Decodable {
    struct Purpose: Decodable {
        var kind: String
        var keyName: String?
        var keyFingerprint: String?
        var processName: String?
        var processPath: String?
        var processId: UInt32?
        var usage: String?
        var hostKeyFingerprint: String?
        var forwarded: Bool?
        var ttlSecs: UInt64?
        var browser: String?
    }
    var purpose: Purpose
    var reason: String
    var userId: String
    var allowBiometrics: Bool
    var allowPassword: Bool
}

enum WireCoding {
    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }()
    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.keyEncodingStrategy = .convertToSnakeCase
        return e
    }()
}
