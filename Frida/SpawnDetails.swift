import CFrida

@objc(FridaSpawnDetails)
public class SpawnDetails: NSObject, NSCopying {
    private let handle: COpaquePointer

    init(handle: COpaquePointer) {
        self.handle = handle
    }

    public func copyWithZone(zone: NSZone) -> AnyObject {
        g_object_ref(gpointer(handle))
        return SpawnDetails(handle: handle)
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var pid: UInt32 {
        return frida_spawn_get_pid(handle)
    }

    public var identifier: String? {
        return String.fromCString(frida_spawn_get_identifier(handle))
    }

    public override var description: String {
        if let identifier = self.identifier {
            return "Frida.SpawnDetails(pid: \(pid), identifier: \"\(identifier)\")"
        } else {
            return "Frida.SpawnDetails(pid: \(pid))"
        }
    }

    public override func isEqual(object: AnyObject?) -> Bool {
        if let details = object as? SpawnDetails {
            return details.handle == handle
        } else {
            return false
        }
    }

    public override var hash: Int {
        return handle.hashValue
    }
}
