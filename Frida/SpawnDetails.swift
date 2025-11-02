import Frida_Private

public final class SpawnDetails: CustomStringConvertible, Equatable, Hashable {
    private let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var pid: UInt {
        return UInt(frida_spawn_get_pid(handle))
    }

    public var identifier: String? {
        if let rawIdentifier = frida_spawn_get_identifier(handle) {
            return String(cString: rawIdentifier)
        }
        return nil
    }

    public var description: String {
        if let identifier = self.identifier {
            return "Frida.SpawnDetails(pid: \(pid), identifier: \"\(identifier)\")"
        } else {
            return "Frida.SpawnDetails(pid: \(pid))"
        }
    }

    public static func == (lhs: SpawnDetails, rhs: SpawnDetails) -> Bool {
        return lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }
}
