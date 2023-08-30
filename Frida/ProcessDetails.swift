import AppKit
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

    @objc public var pid: UInt {
        return UInt(frida_process_get_pid(handle))
    }

    @objc public var name: String {
        return String(cString: frida_process_get_name(handle))
    }

    public lazy var parameters: [String: Any] = {
        var result = Marshal.dictionaryFromParametersDict(frida_process_get_parameters(handle))

        if let started = result["started"] as? String {
            result["started"] = Marshal.dateFromISO8601(started) ?? NSNull()
        }

        return result
    }()

    @objc public lazy var icons: [NSImage] = {
        guard let icons = parameters["icons"] as? [[String: Any]] else {
            return []
        }
        return icons.compactMap(Marshal.iconFromVarDict)
    }()

    public override var description: String {
        return "Frida.ProcessDetails(pid: \(pid), name: \"\(name)\", parameters: \(parameters))"
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
