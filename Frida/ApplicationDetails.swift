import FridaCore

public final class ApplicationDetails: CustomStringConvertible, Equatable, Hashable {
    private let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var identifier: String {
        return String(cString: frida_application_get_identifier(handle))
    }

    public var name: String {
        return String(cString: frida_application_get_name(handle))
    }

    public var pid: UInt? {
        let value = frida_application_get_pid(handle)
        return value != 0 ? UInt(value) : nil
    }

    public lazy var parameters: [String: Any] = {
        return Marshal.dictionaryFromParametersDict(frida_application_get_parameters(handle))
    }()

    public lazy var icons: [Icon] = {
        guard let iconDicts = parameters["icons"] as? [[String: Any]] else {
            return []
        }
        return iconDicts.map(Marshal.iconFromVarDict)
    }()

    public var description: String {
        if let pid = self.pid {
            return "Frida.ApplicationDetails(identifier: \"\(identifier)\", name: \"\(name)\", pid: \(pid), parameters: \(parameters))"
        } else {
            return "Frida.ApplicationDetails(identifier: \"\(identifier)\", name: \"\(name)\", parameters: \(parameters))"
        }
    }

    public static func == (lhs: ApplicationDetails, rhs: ApplicationDetails) -> Bool {
        return lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }
}
