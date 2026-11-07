import AppKit
import Network

/// Forwards OS session events to the core. The core decides (from its settings) whether an
/// event locks the SSH agent; this class only reports what happened.
@MainActor
final class SystemEvents {
    private var observers: [NSObjectProtocol] = []
    private let pathMonitor = NWPathMonitor()
    private var lastPathSatisfied = true

    func start() {
        let ws = NSWorkspace.shared.notificationCenter
        let map: [(Notification.Name, String)] = [
            (NSWorkspace.willSleepNotification, "will_sleep"),
            (NSWorkspace.didWakeNotification, "did_wake"),
            (NSWorkspace.sessionDidResignActiveNotification, "session_resigned"),
            (NSWorkspace.sessionDidBecomeActiveNotification, "session_active"),
        ]
        for (name, event) in map {
            observers.append(ws.addObserver(forName: name, object: nil, queue: .main) { _ in
                SystemEvents.send(event)
            })
        }
        let dnc = DistributedNotificationCenter.default()
        observers.append(dnc.addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main) { _ in
            SystemEvents.send("screen_locked")
        })

        pathMonitor.pathUpdateHandler = { [weak self] path in
            let ok = path.status == .satisfied
            DispatchQueue.main.async {
                guard let self else { return }
                if ok && !self.lastPathSatisfied { SystemEvents.send("network_up") }
                self.lastPathSatisfied = ok
            }
        }
        pathMonitor.start(queue: .global(qos: .utility))
    }

    nonisolated private static func send(_ event: String) {
        Task { await CoreBridge.shared.command("system_event", ["event": event]) }
    }
}
