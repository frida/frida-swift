import CFrida

public class Session : CustomStringConvertible {
    public var delegate: SessionDelegate?

    public typealias DetachComplete = () -> Void

    public typealias CreateScriptComplete = (result: CreateScriptResult) -> Void
    public typealias CreateScriptResult = () throws -> Script

    public typealias EnableDebuggerComplete = (result: EnableDebuggerResult) -> Void
    public typealias EnableDebuggerResult = () throws -> Bool

    public typealias DisableDebuggerComplete = (result: DisableDebuggerResult) -> Void
    public typealias DisableDebuggerResult = () throws -> Bool

    public typealias DisableJitComplete = (result: DisableJitResult) -> Void
    public typealias DisableJitResult = () throws -> Bool

    private typealias DetachedHandler = @convention(c) (session: COpaquePointer, userData: gpointer) -> Void

    private let handle: COpaquePointer
    private var onDetachedHandler: gulong = 0

    init(handle: COpaquePointer) {
        self.handle = handle

        let rawHandle = gpointer(handle)
        onDetachedHandler = g_signal_connect_data(rawHandle, "detached", unsafeBitCast(onDetached, GCallback.self),
                                                  gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                  releaseConnection, GConnectFlags(0))
    }

    deinit {
        let rawHandle = gpointer(handle)
        let handlers = [onDetachedHandler]
        Runtime.scheduleOnFridaThread() {
            for handler in handlers {
                g_signal_handler_disconnect(rawHandle, handler)
            }
            g_object_unref(rawHandle)
        }
    }

    public var pid: UInt {
        return UInt(frida_session_get_pid(handle))
    }

    public var description: String {
        return "Frida.Session(pid: \(pid))"
    }

    public func detach(completionHandler: DetachComplete = {}) {
        Runtime.scheduleOnFridaThread() {
            frida_session_detach(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<DetachComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                frida_session_detach_finish(COpaquePointer(source), result)

                Runtime.scheduleOnMainThread() {
                    operation.completionHandler()
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<DetachComplete>(completionHandler)).toOpaque()))
        }
    }

    public func createScript(name: String, source: String, completionHandler: CreateScriptComplete) {
        Runtime.scheduleOnFridaThread() {
            frida_session_create_script(self.handle, name, source, { source, result, data in
                let operation = Unmanaged<AsyncOperation<CreateScriptComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                let rawScript = frida_session_create_script_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread() {
                        operation.completionHandler() { throw error }
                    }
                    return
                }

                let script = Script(handle: rawScript)

                Runtime.scheduleOnMainThread() {
                    operation.completionHandler() { script }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<CreateScriptComplete>(completionHandler)).toOpaque()))
        }
    }

    public func enableDebugger(port: UInt16 = 0, completionHandler: EnableDebuggerComplete = { _ in }) {
        Runtime.scheduleOnFridaThread() {
            frida_session_enable_debugger(self.handle, port, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnableDebuggerComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                frida_session_enable_debugger_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread() {
                        operation.completionHandler() { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread() {
                    operation.completionHandler() { true }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<EnableDebuggerComplete>(completionHandler)).toOpaque()))
        }
    }

    public func disableDebugger(completionHandler: DisableDebuggerComplete = { _ in }) {
        Runtime.scheduleOnFridaThread() {
            frida_session_disable_debugger(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<DisableDebuggerComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                frida_session_disable_debugger_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread() {
                        operation.completionHandler() { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread() {
                    operation.completionHandler() { true }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<DisableDebuggerComplete>(completionHandler)).toOpaque()))
        }
    }

    public func disableJit(completionHandler: DisableJitComplete = { _ in }) {
        Runtime.scheduleOnFridaThread() {
            frida_session_disable_jit(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<DisableJitComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                frida_session_disable_jit_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread() {
                        operation.completionHandler() { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread() {
                    operation.completionHandler() { true }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<DisableJitComplete>(completionHandler)).toOpaque()))
        }
    }

    private let onDetached: DetachedHandler = { _, userData in
        let connection = Unmanaged<SignalConnection<Session>>.fromOpaque(COpaquePointer(userData)).takeUnretainedValue()

        if let session = connection.instance {
            Runtime.scheduleOnMainThread() {
                session.delegate?.sessionDetached(session)
            }
        }
    }

    private let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<Session>>.fromOpaque(COpaquePointer(data)).release()
    }
}
