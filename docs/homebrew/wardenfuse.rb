# Template for a future Homebrew Cask (requires a notarized release DMG).
cask "wardenfuse" do
  version "0.1.0"
  sha256 "REPLACE_WITH_DMG_SHA256"

  url "https://github.com/Asutorufa/wardenfuse/releases/download/v#{version}/WardenFuse.dmg"
  name "WardenFuse"
  desc "Bitwarden biometric bridge and SSH agent (unofficial)"
  homepage "https://github.com/Asutorufa/wardenfuse"

  depends_on macos: ">= :sequoia"
  depends_on arch: :arm64

  app "WardenFuse.app"

  # WardenFuse removes its own manifests/ssh-config block via Settings → Security →
  # "Remove WardenFuse Data…"; zap only removes WardenFuse-owned paths.
  zap trash: [
    "~/Library/Application Support/WardenFuse",
    "~/.wardenfuse",
  ]
end
