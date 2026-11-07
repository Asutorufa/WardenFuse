#!/usr/bin/env swift
// Generates macos/WardenFuse/Resources/AppIcon.icns (original artwork, no SF Symbols).
//   swift scripts/make-icon.swift
// Layout follows the macOS app icon grid: 1024 canvas, 824 squircle body, centered.
import AppKit

let root = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().deletingLastPathComponent()
let out = root.appendingPathComponent("macos/WardenFuse/Resources")
let iconset = FileManager.default.temporaryDirectory.appendingPathComponent("AppIcon.iconset")
try? FileManager.default.removeItem(at: iconset)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

func rgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: r / 255, green: g / 255, blue: b / 255, alpha: a)
}

func draw(_ ctx: CGContext, size s: CGFloat) {
    let k = s / 1024
    ctx.scaleBy(x: k, y: k)
    let space = CGColorSpace(name: CGColorSpace.sRGB)!

    // Body: continuous-corner squircle.
    let body = CGRect(x: 100, y: 100, width: 824, height: 824)
    let squircle = CGPath(roundedRect: body, cornerWidth: 185, cornerHeight: 185, transform: nil)

    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 28, color: rgb(0, 0, 0, 0.32))
    ctx.addPath(squircle)
    ctx.setFillColor(rgb(40, 44, 52))
    ctx.fillPath()
    ctx.restoreGState()

    // Background gradient: graphite to muted slate (low saturation).
    ctx.saveGState()
    ctx.addPath(squircle)
    ctx.clip()
    let bg = CGGradient(colorsSpace: space, colors: [rgb(78, 92, 110), rgb(33, 38, 47)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(bg, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])
    // Soft top highlight (glass-like rim light).
    let hl = CGGradient(colorsSpace: space, colors: [rgb(255, 255, 255, 0.18), rgb(255, 255, 255, 0)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(hl, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 640), options: [])
    ctx.restoreGState()

    // Inner rim.
    ctx.addPath(CGPath(roundedRect: body.insetBy(dx: 2, dy: 2), cornerWidth: 183, cornerHeight: 183, transform: nil))
    ctx.setStrokeColor(rgb(255, 255, 255, 0.12))
    ctx.setLineWidth(4)
    ctx.strokePath()

    // Shield.
    let shield = CGMutablePath()
    let top: CGFloat = 790, bottom: CGFloat = 228, cx: CGFloat = 512, half: CGFloat = 228
    shield.move(to: CGPoint(x: cx, y: top))
    shield.addCurve(to: CGPoint(x: cx + half, y: top - 70),
                    control1: CGPoint(x: cx + 90, y: top - 40), control2: CGPoint(x: cx + 170, y: top - 60))
    shield.addCurve(to: CGPoint(x: cx, y: bottom),
                    control1: CGPoint(x: cx + half + 6, y: 470), control2: CGPoint(x: cx + 140, y: 300))
    shield.addCurve(to: CGPoint(x: cx - half, y: top - 70),
                    control1: CGPoint(x: cx - 140, y: 300), control2: CGPoint(x: cx - half - 6, y: 470))
    shield.addCurve(to: CGPoint(x: cx, y: top),
                    control1: CGPoint(x: cx - 170, y: top - 60), control2: CGPoint(x: cx - 90, y: top - 40))
    shield.closeSubpath()

    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -8), blur: 18, color: rgb(0, 0, 0, 0.35))
    ctx.addPath(shield)
    ctx.setFillColor(rgb(236, 240, 244))
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(shield)
    ctx.clip()
    let sg = CGGradient(colorsSpace: space, colors: [rgb(250, 252, 253), rgb(206, 214, 222)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(sg, start: CGPoint(x: 512, y: top), end: CGPoint(x: 512, y: bottom), options: [])
    ctx.restoreGState()

    // Keyhole (accent: muted teal).
    let keyhole = CGMutablePath()
    keyhole.addEllipse(in: CGRect(x: cx - 58, y: 520, width: 116, height: 116))
    keyhole.move(to: CGPoint(x: cx - 30, y: 540))
    keyhole.addLine(to: CGPoint(x: cx - 46, y: 380))
    keyhole.addQuadCurve(to: CGPoint(x: cx + 46, y: 380), control: CGPoint(x: cx, y: 366))
    keyhole.addLine(to: CGPoint(x: cx + 30, y: 540))
    keyhole.closeSubpath()
    ctx.addPath(keyhole)
    ctx.setFillColor(rgb(46, 112, 120))
    ctx.fillPath()
}

let sizes: [(String, Int)] = [
    ("16x16", 16), ("16x16@2x", 32), ("32x32", 32), ("32x32@2x", 64),
    ("128x128", 128), ("128x128@2x", 256), ("256x256", 256), ("256x256@2x", 512),
    ("512x512", 512), ("512x512@2x", 1024),
]
for (name, px) in sizes {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    let g = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.current = g
    draw(g.cgContext, size: CGFloat(px))
    NSGraphicsContext.restoreGraphicsState()
    try rep.representation(using: .png, properties: [:])!
        .write(to: iconset.appendingPathComponent("icon_\(name).png"))
}
let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", iconset.path, "-o", out.appendingPathComponent("AppIcon.icns").path]
try p.run()
p.waitUntilExit()
try? FileManager.default.removeItem(at: root.appendingPathComponent("docs/icon.png"))
try? FileManager.default.copyItem(at: iconset.appendingPathComponent("icon_512x512@2x.png"),
                                  to: root.appendingPathComponent("docs/icon.png"))
print("Wrote \(out.appendingPathComponent("AppIcon.icns").path)")
