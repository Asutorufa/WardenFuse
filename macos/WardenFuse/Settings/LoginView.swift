import SwiftUI

/// Bitwarden login (master password with two-step login, or personal API key). The master
/// password is passed to the core once and never stored; the core runs the official SDK login.
struct LoginView: View {
    @EnvironmentObject var core: CoreBridge

    enum Method: String, CaseIterable, Identifiable {
        case password = "Master Password"
        case apiKey = "API Key"
        var id: String { rawValue }
    }

    enum Field: Hashable { case server, email, clientId, clientSecret, password, code }

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
    @FocusState private var focus: Field?

    private static let servers = [
        ("bitwarden.com (US)", "https://vault.bitwarden.com"),
        ("bitwarden.eu (EU)", "https://vault.bitwarden.eu"),
    ]
    private var isCustomServer: Bool { !Self.servers.contains { $0.1 == server } }
    private var inTwoFactor: Bool { !twoFactorMethods.isEmpty }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                if inTwoFactor { twoFactorSection } else { credentialsSections }
                if let error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .accessibilityLabel("Login error: \(error)")
                    }
                }
            }
            .formStyle(.grouped)
            .disabled(busy)

            footer
                .padding(.horizontal, 20)
                .padding(.bottom, 16)
                .padding(.top, 4)
        }
        .frame(minWidth: 420, idealWidth: 460, maxWidth: 720, minHeight: 360, idealHeight: 440, maxHeight: .infinity)
        .onAppear {
            if let s = core.snapshot {
                server = s.settings.serverUrl
                if email.isEmpty { email = s.account.email ?? "" }
            }
            focus = email.isEmpty ? .email : .password
        }
        .onDisappear { password = ""; clientSecret = ""; code = "" }
    }

    @ViewBuilder
    private var credentialsSections: some View {
        Section {
            Picker("Server", selection: Binding(
                get: { isCustomServer ? "custom" : server },
                set: { v in
                    if v != "custom" { server = v } else if !isCustomServer { server = "https://"; focus = .server }
                })) {
                ForEach(Self.servers, id: \.1) { Text($0.0).tag($0.1) }
                Text("Self-hosted").tag("custom")
            }
            if isCustomServer {
                TextField("Server URL", text: $server, prompt: Text("https://vault.example.com"))
                    .textContentType(.URL)
                    .focused($focus, equals: .server)
                    .onSubmit { focus = method == .password ? .email : .clientId }
            }
            Picker("Log in with", selection: $method) {
                ForEach(Method.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
        }
        Section {
            if method == .password {
                TextField("Email", text: $email, prompt: Text("name@example.com"))
                    .textContentType(.username)
                    .focused($focus, equals: .email)
                    .onSubmit { focus = .password }
            } else {
                TextField("client_id", text: $clientId, prompt: Text("user.xxxxxxxx"))
                    .focused($focus, equals: .clientId)
                    .onSubmit { focus = .clientSecret }
                SecureField("client_secret", text: $clientSecret)
                    .focused($focus, equals: .clientSecret)
                    .onSubmit { focus = .password }
            }
            SecureField("Master password", text: $password)
                .textContentType(.password)
                .focused($focus, equals: .password)
                .onSubmit { Task { await submit(sendEmail: false) } }
        } footer: {
            Text(method == .password
                 ? "Your master password unlocks your vault key once; the key is then protected by the macOS Keychain. The password is never stored."
                 : "Use the personal API key from the Bitwarden web vault (Settings \u{2192} Security \u{2192} Keys). It avoids new-device email verification.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var twoFactorSection: some View {
        Section {
            Picker("Method", selection: $selected2FA) {
                ForEach(twoFactorMethods, id: \.self) { Text(label2FA($0)).tag($0) }
            }
            TextField("Verification code", text: $code)
                .textContentType(.oneTimeCode)
                .focused($focus, equals: .code)
                .onSubmit { Task { await submit(sendEmail: false) } }
            Toggle("Remember this Mac", isOn: $remember)
            if selected2FA == "email" {
                Button("Send Code by Email") { Task { await submit(sendEmail: true) } }
            }
        } header: {
            Text("Two-step login")
        } footer: {
            if !unsupported.isEmpty {
                Text("Not supported by WardenFuse: \(unsupported.joined(separator: ", ")).")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
        .onAppear { focus = .code }
    }

    private var footer: some View {
        HStack(spacing: 10) {
            if inTwoFactor {
                Button("Back") { twoFactorMethods = []; code = ""; error = nil; focus = .password }
                    .glassButtonStyle()
            }
            if busy {
                ProgressView().controlSize(.small)
                Text("Logging in\u{2026}").foregroundStyle(.secondary)
            }
            Spacer()
            GlassGroup {
                HStack(spacing: 10) {
                    Button("Cancel") { WindowManager.shared.closeLogin() }
                        .keyboardShortcut(.cancelAction)
                        .glassButtonStyle()
                    Button(inTwoFactor ? "Verify" : "Log In") { Task { await submit(sendEmail: false) } }
                        .keyboardShortcut(.defaultAction)
                        .glassButtonStyle(prominent: true)
                        .disabled(busy || password.isEmpty || (inTwoFactor && code.isEmpty))
                }
            }
        }
        .controlSize(.large)
    }

    private func label2FA(_ m: String) -> String {
        switch m {
        case "authenticator": "Authenticator app"
        case "email": "Email"
        case "yubikey": "YubiKey OTP"
        default: m
        }
    }

    private func submit(sendEmail: Bool) async {
        guard !busy else { return }
        busy = true
        error = nil
        defer { busy = false }
        var args: [String: Any] = ["server_url": server, "password": password]
        let cmd: String
        if method == .password {
            cmd = "login"
            args["email"] = email
            if inTwoFactor {
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
            WindowManager.shared.closeLogin()
            return
        }
        if let tf = r["two_factor"] as? [String] {
            twoFactorMethods = tf
            unsupported = r["unsupported"] as? [String] ?? []
            if !tf.contains(selected2FA), let first = tf.first { selected2FA = first }
            if tf.isEmpty { error = "This account only offers two-step methods WardenFuse does not support." }
            focus = .code
            return
        }
        error = r["error"] as? String ?? "Login failed"
        focus = .password
    }
}
