import CFrida

public class ProcessDetails : CustomStringConvertible {
    private let handle: COpaquePointer

    init(handle: COpaquePointer) {
        self.handle = handle
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var pid: UInt {
        return UInt(frida_process_get_pid(handle))
    }

    public var name: String {
        return String.fromCString(frida_process_get_name(handle))!
    }

    public var smallIcon: NSImage? {
        return Marshal.imageFromIcon(frida_process_get_small_icon(handle))
    }

    public var largeIcon: NSImage? {
        return Marshal.imageFromIcon(frida_process_get_large_icon(handle))
    }

    public var description: String {
        return "Frida.ProcessDetails(pid: \(pid), name: \"\(name)\")"
    }
}