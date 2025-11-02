import Frida_Private

public final class ChildDetails: CustomStringConvertible, Equatable, Hashable {
    private let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var pid: UInt {
        return UInt(frida_child_get_pid(handle))
    }

    public var parentPid: UInt {
        return UInt(frida_child_get_parent_pid(handle))
    }

    public var origin: ChildOrigin {
        return ChildOrigin(rawValue: frida_child_get_origin(handle).rawValue)!
    }

    public var identifier: String? {
        if let rawIdentifier = frida_child_get_identifier(handle) {
            return String(cString: rawIdentifier)
        }
        return nil
    }

    public var path: String? {
        if let rawPath = frida_child_get_path(handle) {
            return String(cString: rawPath)
        }
        return nil
    }

    public var argv: [String]? {
        if let rawArgv = frida_child_get_argv(handle, nil) {
            return Marshal.arrayFromStrv(rawArgv)
        }
        return nil
    }

    public var envp: [String: String]? {
        if let rawEnvp = frida_child_get_envp(handle, nil) {
            return Marshal.dictionaryFromEnvp(rawEnvp)
        }
        return nil
    }

    public var description: String {
        return "Frida.ChildDetails(pid: \(pid), parentPid: \(parentPid), origin: \(origin), identifier: \(String(describing: identifier)), path: \(String(describing: path)), argv: \(String(describing: argv)), envp: \(String(describing: envp)))"
    }

    public static func == (lhs: ChildDetails, rhs: ChildDetails) -> Bool {
        return lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }
}

@frozen
public enum ChildOrigin: UInt32, CustomStringConvertible {
    case fork
    case exec
    case spawn

    public var description: String {
        switch self {
        case .fork: return "fork"
        case .exec: return "exec"
        case .spawn: return "spawn"
        }
    }
}
