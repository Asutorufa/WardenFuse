import SwiftUI

/// Liquid Glass is applied only to controls that float above content (action buttons in the
/// menu bar window, window footer actions). Lists, forms, sidebars, toolbars and the menu bar
/// window itself are drawn by the system, which already uses Liquid Glass on macOS 26+; no extra
/// glass, blur or background is layered on top of them.
extension View {
    /// `.glass` / `.glassProminent` on macOS 26+, standard bordered styles before.
    @ViewBuilder
    func glassButtonStyle(prominent: Bool = false) -> some View {
        if #available(macOS 26.0, *) {
            if prominent {
                buttonStyle(.glassProminent)
            } else {
                buttonStyle(.glass)
            }
        } else {
            if prominent {
                buttonStyle(.borderedProminent)
            } else {
                buttonStyle(.bordered)
            }
        }
    }
}

/// Groups neighbouring glass controls so they share one sampling region and blend together
/// (`GlassEffectContainer`, macOS 26+).
struct GlassGroup<Content: View>: View {
    var spacing: CGFloat = 8
    @ViewBuilder var content: Content

    var body: some View {
        if #available(macOS 26.0, *) {
            GlassEffectContainer(spacing: spacing) { content }
        } else {
            content
        }
    }
}
