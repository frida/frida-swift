import FridaCore

public protocol WebRequestDelegate: AnyObject {
    func handleRequest(_ request: WebRequest) async throws -> WebResponse?
}

public final class CustomWebRequestHandler: @unchecked Sendable, WebRequestHandler {
    public let handle: OpaquePointer

    public init(_ delegate: WebRequestDelegate) {
        Runtime.ensureInitialized()

        self.handle = CustomWebRequestHandler.makeInstance(for: delegate)
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    private static let quark: GQuark = {
        let key = "frida-custom-web-request-handler"
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

        let typeName = "FridaSwiftWebRequestHandler"
        let type: GType = typeName.withCString { cStr in
            g_type_register_static(
                g_type_from_name("GObject"),
                cStr,
                &info,
                GTypeFlags(rawValue: 0)
            )
        }

        var ifaceInfo = GInterfaceInfo(
            interface_init: { ifacePtr, _ in
                guard let ifacePtr else { return }
                let iface = ifacePtr.assumingMemoryBound(to: FridaWebRequestHandlerIface.self)
                iface.pointee.handle_request = CustomWebRequestHandler.handleRequestThunk
                iface.pointee.handle_request_finish = CustomWebRequestHandler.handleRequestFinishThunk
            },
            interface_finalize: nil,
            interface_data: nil
        )

        let handlerIfaceType = frida_web_request_handler_get_type()
        g_type_add_interface_static(type, handlerIfaceType, &ifaceInfo)

        return type
    }

    private static func makeInstance(for delegate: WebRequestDelegate) -> OpaquePointer {
        let type = gType

        guard let raw = g_object_new_with_properties(type, 0, nil, nil) else {
            fatalError("Failed to create FridaSwiftWebRequestHandler GObject")
        }

        let gobj = UnsafeMutableRawPointer(raw).assumingMemoryBound(to: GObject.self)

        let box = SwiftWebBox(delegate)
        let unmanaged = Unmanaged.passRetained(box)

        g_object_set_qdata_full(
            gobj,
            quark,
            unmanaged.toOpaque(),
            { data in
                if let data {
                    Unmanaged<SwiftWebBox>.fromOpaque(data).release()
                }
            }
        )

        return OpaquePointer(raw)
    }

    private static func getBox(from handler: OpaquePointer) -> SwiftWebBox? {
        let instance = UnsafeMutableRawPointer(handler).assumingMemoryBound(to: GTypeInstance.self)
        let gobj = UnsafeMutableRawPointer(instance).assumingMemoryBound(to: GObject.self)

        guard let data = g_object_get_qdata(gobj, quark) else {
            return nil
        }

        return Unmanaged<SwiftWebBox>.fromOpaque(data).takeUnretainedValue()
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

    private static let handleRequestThunk: @convention(c) (
        OpaquePointer?,
        OpaquePointer?,
        UnsafeMutablePointer<GCancellable>?,
        GAsyncReadyCallback?,
        gpointer?
    ) -> Void = { selfPtr, requestPtr, cancellable, callback, userData in
        let box = CustomWebRequestHandler.getBox(from: selfPtr!)!

        let request = WebRequest(handle: requestPtr!)

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
                let response = try await box.delegate.handleRequest(request)
                if let response {
                    g_object_ref(gpointer(response.handle))
                    g_task_return_pointer(
                        task,
                        UnsafeMutableRawPointer(response.handle),
                        { ptr in
                            if let ptr {
                                g_object_unref(ptr)
                            }
                        }
                    )
                } else {
                    g_task_return_pointer(task, nil, nil)
                }
            } catch {
                if let gerr = CustomWebRequestHandler.makeGError(from: error) {
                    g_task_return_error(task, gerr)
                } else {
                    "Request handler failed".withCString { cStr in
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

    private static let handleRequestFinishThunk: @convention(c) (
        OpaquePointer?,
        OpaquePointer?,
        UnsafeMutablePointer<UnsafeMutablePointer<GError>?>?
    ) -> OpaquePointer? = { _, resultPtr, errorOut in
        let task = resultPtr

        guard let raw = g_task_propagate_pointer(task, errorOut) else {
            return nil
        }

        return OpaquePointer(raw)
    }

    private final class SwiftWebBox {
        let delegate: WebRequestDelegate

        init(_ delegate: WebRequestDelegate) {
            self.delegate = delegate
        }
    }
}
