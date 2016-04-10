import CFrida

@objc(FridaApplicationDetails)
public class ApplicationDetails: NSObject, NSCopying {
    private let handle: COpaquePointer

    init(handle: COpaquePointer) {
        self.handle = handle
    }

    public func copyWithZone(zone: NSZone) -> AnyObject {
        g_object_ref(gpointer(handle))
        return ApplicationDetails(handle: handle)
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var identifier: String {
        return String.fromCString(frida_application_get_identifier(handle))!
    }

    public var name: String {
        return String.fromCString(frida_application_get_name(handle))!
    }

    public var pid: UInt32? {
        let value = frida_application_get_pid(handle)
        return value != 0 ? value : nil
    }

    public var smallIcon: NSImage? {
        return Marshal.imageFromIcon(frida_application_get_small_icon(handle))
    }

    public var largeIcon: NSImage? {
        return Marshal.imageFromIcon(frida_application_get_large_icon(handle))
    }

    public override var description: String {
        if let pid = self.pid {
            return "Frida.ApplicationDetails(identifier: \"\(identifier)\", name: \"\(name)\", pid: \(pid))"
        } else {
            return "Frida.ApplicationDetails(identifier: \"\(identifier)\", name: \"\(name)\")"
        }
    }

    public override func isEqual(object: AnyObject?) -> Bool {
        if let details = object as? ApplicationDetails {
            return details.handle == handle
        } else {
            return false
        }
    }

    public override var hash: Int {
        return handle.hashValue
    }
}
