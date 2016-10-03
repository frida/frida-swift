import CFrida

@objc(FridaProcessDetails)
public class ProcessDetails: NSObject, NSCopying {
    private let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    public func copy(with zone: NSZone?) -> Any {
        g_object_ref(gpointer(handle))
        return ProcessDetails(handle: handle)
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var pid: UInt {
        return UInt(frida_process_get_pid(handle))
    }

    public var name: String {
        return String(cString: frida_process_get_name(handle))
    }

    public var smallIcon: NSImage? {
        return Marshal.imageFromIcon(frida_process_get_small_icon(handle))
    }

    public var largeIcon: NSImage? {
        return Marshal.imageFromIcon(frida_process_get_large_icon(handle))
    }

    public override var description: String {
        return "Frida.ProcessDetails(pid: \(pid), name: \"\(name)\")"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        if let details = object as? ProcessDetails {
            return details.handle == handle
        } else {
            return false
        }
    }

    public override var hash: Int {
        return handle.hashValue
    }
}
