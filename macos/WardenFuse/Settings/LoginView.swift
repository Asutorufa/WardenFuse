import SwiftUI

/// Bitwarden login (master password with 2FA, or personal API key). The master password is
/// sent to the core once and never stored; the core runs the official SDK login.
struct LoginView: View {
    @EnvironmentObject var core: CoreBridge
    @Environment(\.dismissWindow) private var dismissWindow

    enum Method: String, CaseIterable, Identifiable {
        case password = "Master password"
        case apiKey = "API key"
        var id: String { rawValue }
    }

    @State private var method: Method = .password
    @State private var server = "https://vault.bitwarden.com"
    @State private var email = ""
    @State private var password = ""
    @State private var clientId = ""
    @State private var clientSecret = ""
    @State private var twoFactorMethods: [String] = []
    @State private var unsupported: [String] = []
    @State private var selected2FA = "authenticator"
    @State private var code = ""
    @State private var remember = false
    @State private var busy = false
    @State private var error: String?

    private static let servers = [
        ("Bitwarden (US)", "https://vault.bitwarden.com"),
        ("Bitwarden (EU)", "https://vault.bitwarden.eu"),
    ]

    var body: some View {
        Form {
            Section {
                Picker("Server", selection: Binding(
                    get: { Self.servers.contains { $0.1 == server } ? server : "custom" },
                    set: { if $0 != "custom" { server = $0 } else if Self.servers.contains(where: { $0.1 == server }) { server = "https://" } }
                )) {
                    ForEach(Self.servers, id: \.1) { Text($0.0).tag($0.1) }
                    Text("Self-hosted / Vaultwarden").tag("custom")
                }
                if !Self.servers.contains(where: { $0.1 == server }) {
                    TextField("Server URL", text: $server, prompt: Text("https://vault.example.com"))
                        .textContentType(.URL)
                }
                Picker("Method", selection: $method) {
                    ForEach(Method.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
            }

            if twoFactorMethods.isEmpty {
                Section {
                    if method == .password {
                        TextField("Email", text: $email).textContentType(.username)
                    } else {
                        TextField("client_id", text: $clientId)
                        SecureField("client_secret", text: $clientSecret)
                    }
                    SecureField("Master password", text: $password).textContentType(.password)
                } footer: {
                    Text(method == .password
                         ? "Your master password is used once to unlock your vault key, which is then protected by the macOS Keychain. It is never stored."
                         : "Use the personal API key from the Bitwarden web vault (Settings → Security → Keys). It avoids new-device email verification.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Section("Two-step login") {
                    Picker("Method", selection: $selected2FA) {
                        ForEach(twoFactorMethods, id: \.self) { Text(label2FA($0)).tag($0) }
                    }
                    TextField("Code", text: $code).textContentType(.oneTimeCode)
                    Toggle("Remember this device", isOn: $remember)
                    if selected2FA == "email" {
                        Button("Send code by email") { Task { await submit(sendEmail: true) } }
                            .disabled(busy)
                    }
                    if !unsupported.isEmpty {
                        Text("Not supported by WardenFuse: \(unsupported.joined(separator: ", "))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            if let error {
                Text(error).foregroundStyle(.red).font(.callout)
            }

            HStack {
                if !twoFactorMethods.isEmpty {
                    Button("Back") { twoFactorMethods = []; code = "" }
                }
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("Cancel") { dismissWindow(id: "login") }
                Button("Log In") { Task { await submit(sendEmail: false) } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy || password.isEmpty)
            }
        }
        .formStyle(.grouped)
        .frame(width: 420)
        .onAppear {
            if let s = core.snapshot { server = s.settings.serverUrl; email = s.account.email ?? email }
        }
        .onDisappear { password = ""; clientSecret = ""; code = "" }
    }

    private func label2FA(_ m: String) -> String {
        switch m {
        case "authenticator": return "Authenticator app"
        case "email": return "Email"
        case "yubikey": return "YubiKey OTP"
        default: return m
        }
    }

    private func submit(sendEmail: Bool) async {
        busy = true
        error = nil
        defer { busy = false }
        var args: [String: Any] = ["server_url": server, "password": password]
        let cmd: String
        if method == .password {
            cmd = "login"
            args["email"] = email
            if !twoFactorMethods.isEmpty {
                args["two_factor"] = ["method": selected2FA, "code": sendEmail ? "" : code, "remember": remember]
            }
        } else {
            cmd = "login_api_key"
            args["client_id"] = clientId
            args["client_secret"] = clientSecret
        }
        let r = await core.command(cmd, args)
        if r["ok"] as? Bool == true {
            password = ""; clientSecret = ""; code = ""
            dismissWindow(id: "login")
            return
        }
        if let tf = r["two_factor"] as? [String] {
            twoFactorMethods = tf
            unsupported = r["unsupported"] as? [String] ?? []
            if !tf.contains(selected2FA), let first = tf.first { selected2FA = first }
            if tf.isEmpty { error = "This account only offers two-step methods WardenFuse does not support." }
            return
        }
        error = r["error"] as? String ?? "Login failed"
    }
}
