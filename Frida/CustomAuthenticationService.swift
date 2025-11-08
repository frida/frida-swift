import Frida_Private

public protocol AuthenticationDelegate: AnyObject {
    func authenticate(token: String) async throws -> String
}

public final class CustomAuthenticationService: @unchecked Sendable, AuthenticationService {
    public let handle: OpaquePointer

    public init(_ delegate: AuthenticationDelegate) {
        Runtime.ensureInitialized()

        self.handle = CustomAuthenticationService.makeInstance(for: delegate)
    }

    private static let quark: GQuark = {
        let key = "frida-swift-authentication-service"
        return key.withCString { cStr in
            g_quark_from_string(cStr)
        }
    }()

    private static let gType: GType = {
        registerType()
    }()

    private static func registerType() -> GType {
        var info = GTypeInfo(
            class_size: guint16(MemoryLayout<GObjectClass>.stride),
            base_init: nil,
            base_finalize: nil,
            class_init: { _, _ in
            },
            class_finalize: nil,
            class_data: nil,
            instance_size: guint16(MemoryLayout<GObject>.stride),
            n_preallocs: 0,
            instance_init: { _, _ in
            },
            value_table: nil
        )

        let typeName = "FridaSwiftAuthenticationService"
        let type: GType = typeName.withCString { cStr in
            g_type_register_static(
                g_type_from_name("GObject"),
                cStr,
                &info,
                GTypeFlags(0)
            )
        }

        var ifaceInfo = GInterfaceInfo(
            interface_init: { ifacePtr, _ in
                guard let ifacePtr else { return }
                let iface = ifacePtr.assumingMemoryBound(to: FridaAuthenticationServiceIface.self)
                iface.pointee.authenticate = CustomAuthenticationService.authenticateThunk
                iface.pointee.authenticate_finish = CustomAuthenticationService.authenticateFinishThunk
            },
            interface_finalize: nil,
            interface_data: nil
        )

        let authIfaceType = frida_authentication_service_get_type()
        g_type_add_interface_static(type, authIfaceType, &ifaceInfo)

        return type
    }

    private static func makeInstance(for delegate: AuthenticationDelegate) -> OpaquePointer {
        let type = gType

        guard let raw = g_object_new_with_properties(type, 0, nil, nil) else {
            fatalError("Failed to create FridaSwiftAuthenticationService GObject")
        }

        let gobj = UnsafeMutableRawPointer(raw).assumingMemoryBound(to: GObject.self)

        let box = SwiftAuthBox(delegate)
        let unmanaged = Unmanaged.passRetained(box)

        g_object_set_qdata_full(
            gobj,
            quark,
            unmanaged.toOpaque(),
            { data in
                if let data {
                    Unmanaged<SwiftAuthBox>.fromOpaque(data).release()
                }
            }
        )

        return OpaquePointer(raw)
    }

    private static func getBox(
        from auth: OpaquePointer
    ) -> SwiftAuthBox? {
        let instance = UnsafeMutableRawPointer(auth).assumingMemoryBound(to: GTypeInstance.self)
        let gobj = UnsafeMutableRawPointer(instance).assumingMemoryBound(to: GObject.self)

        guard let data = g_object_get_qdata(gobj, quark) else {
            return nil
        }

        return Unmanaged<SwiftAuthBox>.fromOpaque(data).takeUnretainedValue()
    }

    private static func makeGError(from error: Swift.Error) -> UnsafeMutablePointer<GError>? {
        let description = String(describing: error)
        var errorPtr: UnsafeMutablePointer<GError>?

        description.withCString { cStr in
            errorPtr = g_error_new_literal(
                frida_error_quark(),
                0,
                cStr
            )
        }

        return errorPtr
    }

    private static let authenticateThunk: @convention(c) (
        OpaquePointer?,
        UnsafePointer<CChar>?,
        UnsafeMutablePointer<GCancellable>?,
        GAsyncReadyCallback?,
        gpointer?
    ) -> Void = { selfPtr, rawToken, cancellable, callback, userData in
        let box = CustomAuthenticationService.getBox(from: selfPtr!)!

        let token: String = rawToken.map { Marshal.stringFromCString($0) } ?? ""

        guard let task = g_task_new(
            UnsafeMutableRawPointer(selfPtr),
            cancellable,
            callback,
            userData
        ) else {
            return
        }

        Task.detached {
            do {
                let sessionInfo = try await box.delegate.authenticate(token: token)

                sessionInfo.withCString { cStr in
                    let cString = UnsafeMutableRawPointer(g_strdup(cStr))
                    g_task_return_pointer(
                        task,
                        cString,
                        { ptr in
                            if let ptr {
                                g_free(ptr)
                            }
                        }
                    )
                }
            } catch {
                if let gerr = CustomAuthenticationService.makeGError(from: error) {
                    g_task_return_error(task, gerr)
                } else {
                    "Authentication failed".withCString { cStr in
                        let gerr = g_error_new_literal(
                            frida_error_quark(),
                            0,
                            cStr
                        )
                        g_task_return_error(task, gerr)
                    }
                }
            }

            g_object_unref(gpointer(task))
        }
    }

    private static let authenticateFinishThunk: @convention(c) (
        OpaquePointer?,
        OpaquePointer?,
        UnsafeMutablePointer<UnsafeMutablePointer<GError>?>?
    ) -> UnsafeMutablePointer<CChar>? = { _, resultPtr, errorOut in
        let task = resultPtr

        let raw = g_task_propagate_pointer(task, errorOut)

        return raw?.assumingMemoryBound(to: CChar.self)
    }

    private final class SwiftAuthBox {
        let delegate: AuthenticationDelegate

        init(_ delegate: AuthenticationDelegate) {
            self.delegate = delegate
        }
    }
}
