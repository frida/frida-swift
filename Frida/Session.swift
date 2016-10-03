import CFrida

@objc(FridaSession)
public class Session: NSObject, NSCopying {
    public weak var delegate: SessionDelegate?

    public typealias DetachComplete = () -> Void

    public typealias CreateScriptComplete = (_ result: CreateScriptResult) -> Void
    public typealias CreateScriptResult = () throws -> Script

    public typealias EnableDebuggerComplete = (_ result: EnableDebuggerResult) -> Void
    public typealias EnableDebuggerResult = () throws -> Bool

    public typealias DisableDebuggerComplete = (_ result: DisableDebuggerResult) -> Void
    public typealias DisableDebuggerResult = () throws -> Bool

    public typealias DisableJitComplete = (_ result: DisableJitResult) -> Void
    public typealias DisableJitResult = () throws -> Bool

    private typealias DetachedHandler = @convention(c) (_ session: OpaquePointer, _ userData: gpointer) -> Void

    private let handle: OpaquePointer
    private var onDetachedHandler: gulong = 0

    init(handle: OpaquePointer) {
        self.handle = handle

        super.init()

        let rawHandle = gpointer(handle)
        onDetachedHandler = g_signal_connect_data(rawHandle, "detached", unsafeBitCast(onDetached, to: GCallback.self),
                                                  gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                  releaseConnection, GConnectFlags(0))
    }

    public func copy(with zone: NSZone?) -> Any {
        g_object_ref(gpointer(handle))
        return Session(handle: handle)
    }

    deinit {
        let rawHandle = gpointer(handle)
        let handlers = [onDetachedHandler]
        Runtime.scheduleOnFridaThread {
            for handler in handlers {
                g_signal_handler_disconnect(rawHandle, handler)
            }
            g_object_unref(rawHandle)
        }
    }

    public var pid: UInt {
        return UInt(frida_session_get_pid(handle))
    }

    public override var description: String {
        return "Frida.Session(pid: \(pid))"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        if let session = object as? Session {
            return session.handle == handle
        } else {
            return false
        }
    }

    public override var hash: Int {
        return handle.hashValue
    }

    public func detach(_ completionHandler: @escaping DetachComplete = {}) {
        Runtime.scheduleOnFridaThread {
            frida_session_detach(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<DetachComplete>>.fromOpaque(data!).takeRetainedValue()

                frida_session_detach_finish(OpaquePointer(source), result)

                Runtime.scheduleOnMainThread {
                    operation.completionHandler()
                }
            }, Unmanaged.passRetained(AsyncOperation<DetachComplete>(completionHandler)).toOpaque())
        }
    }

    public func createScript(_ name: String, source: String, completionHandler: @escaping CreateScriptComplete) {
        Runtime.scheduleOnFridaThread {
            frida_session_create_script(self.handle, name, source, { source, result, data in
                let operation = Unmanaged<AsyncOperation<CreateScriptComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawScript = frida_session_create_script_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let script = Script(handle: rawScript!)

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { script }
                }
            }, Unmanaged.passRetained(AsyncOperation<CreateScriptComplete>(completionHandler)).toOpaque())
        }
    }

    public func enableDebugger(_ port: UInt16 = 0, completionHandler: @escaping EnableDebuggerComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_session_enable_debugger(self.handle, port, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnableDebuggerComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_session_enable_debugger_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, Unmanaged.passRetained(AsyncOperation<EnableDebuggerComplete>(completionHandler)).toOpaque())
        }
    }

    public func disableDebugger(_ completionHandler: @escaping DisableDebuggerComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_session_disable_debugger(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<DisableDebuggerComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_session_disable_debugger_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, Unmanaged.passRetained(AsyncOperation<DisableDebuggerComplete>(completionHandler)).toOpaque())
        }
    }

    public func disableJit(_ completionHandler: @escaping DisableJitComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_session_disable_jit(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<DisableJitComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_session_disable_jit_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, Unmanaged.passRetained(AsyncOperation<DisableJitComplete>(completionHandler)).toOpaque())
        }
    }

    private let onDetached: DetachedHandler = { _, userData in
        let connection = Unmanaged<SignalConnection<Session>>.fromOpaque(userData).takeUnretainedValue()

        if let session = connection.instance {
            Runtime.scheduleOnMainThread {
                session.delegate?.sessionDetached(session)
            }
        }
    }

    private let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<Session>>.fromOpaque(data!).release()
    }
}
