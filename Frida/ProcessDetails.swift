import FridaCore

public final class ProcessDetails: CustomStringConvertible, Equatable, Hashable, Identifiable {
    private let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
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

    public lazy var parameters: [String: Any] = {
        return Marshal.dictionaryFromParametersDict(frida_process_get_parameters(handle))
    }()

    public lazy var icons: [Icon] = {
        guard let iconDicts = parameters["icons"] as? [[String: Any]] else {
            return []
        }
        return iconDicts.map(Marshal.iconFromVarDict)
    }()

    public var description: String {
        return "Frida.ProcessDetails(pid: \(pid), name: \"\(name)\", parameters: \(parameters))"
    }

    public static func == (lhs: ProcessDetails, rhs: ProcessDetails) -> Bool {
        return lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }

    public var id: UInt {
        return pid
    }
}
