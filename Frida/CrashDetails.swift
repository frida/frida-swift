import FridaCore

public final class CrashDetails: CustomStringConvertible, Equatable, Hashable {
    private let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var pid: UInt {
        return UInt(frida_crash_get_pid(handle))
    }

    public var processName: String {
        return String(cString: frida_crash_get_process_name(handle))
    }

    public var summary: String {
        return String(cString: frida_crash_get_summary(handle))
    }

    public var report: String {
        return String(cString: frida_crash_get_report(handle))
    }

    public lazy var parameters: [String: Any] = {
        return Marshal.dictionaryFromParametersDict(frida_crash_get_parameters(handle))
    }()

    public var description: String {
        return "Frida.CrashDetails(pid: \(pid), processName: \"\(processName)\", summary: \"\(summary)\")"
    }

    public static func == (lhs: CrashDetails, rhs: CrashDetails) -> Bool {
        return lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }
}
