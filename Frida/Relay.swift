import Frida_Private

public final class Relay: CustomStringConvertible, Equatable, Hashable {
    internal let handle: OpaquePointer

    init(address: String, username: String, password: String, kind: RelayKind) {
        self.handle = frida_relay_new(address, username, password, FridaRelayKind(kind.rawValue))
    }

    private init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var address: String {
        return String(cString: frida_relay_get_address(handle))
    }

    public var username: String {
        return String(cString: frida_relay_get_username(handle))
    }

    public var password: String {
        return String(cString: frida_relay_get_password(handle))
    }

    public var kind: RelayKind {
        return RelayKind(rawValue: frida_relay_get_kind(handle).rawValue)!
    }

    public var description: String {
        return "Frida.Relay(address: \"\(address)\", username: \"\(username)\", password: \"\(password)\", kind: \(kind))"
    }

    public static func == (lhs: Relay, rhs: Relay) -> Bool {
        return lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }
}

public enum RelayKind: UInt32, CustomStringConvertible {
    case turnUdp
    case turnTcp
    case turnTls

    public var description: String {
        switch self {
        case .turnUdp: return "turnUdp"
        case .turnTcp: return "turnTcp"
        case .turnTls: return "turnTls"
        }
    }
}
