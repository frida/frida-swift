import CFrida

public class SpawnDetails : CustomStringConvertible {
    private let handle: COpaquePointer

    init(handle: COpaquePointer) {
        self.handle = handle
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

    public var description: String {
        if let identifier = self.identifier {
            return "Frida.SpawnDetails(pid: \(pid), identifier: \"\(identifier)\")"
        } else {
            return "Frida.SpawnDetails(pid: \(pid))"
        }
    }
}
