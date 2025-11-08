import Frida_Private

public final class EndpointParameters: @unchecked Sendable, CustomStringConvertible, Equatable, Hashable {
    internal let handle: OpaquePointer

    public convenience init(
        address: String? = nil,
        port: UInt16 = 0,
        certificate: TlsCertificate? = nil,
        origin: String? = nil,
        authService: AuthenticationService? = nil,
        assetRoot: File? = nil
    ) {
        Runtime.ensureInitialized()

        self.init(handle: frida_endpoint_parameters_new(
            address,
            port,
            UnsafeMutablePointer<GTlsCertificate>(certificate?.handle),
            origin,
            authService?.handle,
            assetRoot?.handle
        ))
    }

    public init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var description: String {
        "Frida.EndpointParameters(address: \(address ?? "nil"), port: \(port))"
    }

    public static func == (lhs: EndpointParameters, rhs: EndpointParameters) -> Bool {
        lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }

    public var address: String? {
        guard let raw = frida_endpoint_parameters_get_address(handle) else { return nil }
        return Marshal.stringFromCString(raw)
    }

    public var port: UInt16 {
        frida_endpoint_parameters_get_port(handle)
    }

    public var origin: String? {
        guard let raw = frida_endpoint_parameters_get_origin(handle) else { return nil }
        return Marshal.stringFromCString(raw)
    }

    public var assetRoot: File? {
        get {
            guard let raw = frida_endpoint_parameters_get_asset_root(handle) else { return nil }
            g_object_ref(gpointer(raw))
            return File(handle: raw)
        }
        set {
            frida_endpoint_parameters_set_asset_root(handle, newValue?.handle)
        }
    }
}
