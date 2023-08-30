import CFrida
import Foundation

@objc(FridaSession)
public class Session: NSObject, NSCopying {
    public weak var delegate: SessionDelegate?

    public typealias DetachComplete = () -> Void

    public typealias ResumeComplete = (_ result: ResumeResult) -> Void
    public typealias ResumeResult = () throws -> Bool

    public typealias EnableChildGatingComplete = (_ result: EnableChildGatingResult) -> Void
    public typealias EnableChildGatingResult = () throws -> Bool

    public typealias DisableChildGatingComplete = (_ result: DisableChildGatingResult) -> Void
    public typealias DisableChildGatingResult = () throws -> Bool

    public typealias CreateScriptComplete = (_ result: CreateScriptResult) -> Void
    public typealias CreateScriptResult = () throws -> Script

    public typealias CompileScriptComplete = (_ result: CompileScriptResult) -> Void
    public typealias CompileScriptResult = () throws -> Data

    public typealias SetupPeerConnectionComplete = (_ result: SetupPeerConnectionResult) -> Void
    public typealias SetupPeerConnectionResult = () throws -> Bool

    public typealias JoinPortalComplete = (_ result: JoinPortalResult) -> Void
    public typealias JoinPortalResult = () throws -> PortalMembership

    private typealias DetachedHandler = @convention(c) (_ session: OpaquePointer, _ reason: Int, _ crash: OpaquePointer?, _ userData: gpointer) -> Void

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

    public var persistTimeout: UInt {
        return UInt(frida_session_get_persist_timeout(handle))
    }

    public var isDetached: Bool {
        return frida_session_is_detached(handle) != 0
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
            frida_session_detach(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<DetachComplete>>.fromOpaque(data!).takeRetainedValue()

                frida_session_detach_finish(OpaquePointer(source), result, nil)

                Runtime.scheduleOnMainThread {
                    operation.completionHandler()
                }
            }, Unmanaged.passRetained(AsyncOperation<DetachComplete>(completionHandler)).toOpaque())
        }
    }

    public func resume(_ completionHandler: @escaping ResumeComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_session_resume(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<ResumeComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_session_resume_finish(OpaquePointer(source), result, &rawError)
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
            }, Unmanaged.passRetained(AsyncOperation<ResumeComplete>(completionHandler)).toOpaque())
        }
    }

    public func enableChildGating(_ completionHandler: @escaping EnableChildGatingComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_session_enable_child_gating(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnableChildGatingComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_session_enable_child_gating_finish(OpaquePointer(source), result, &rawError)
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
            }, Unmanaged.passRetained(AsyncOperation<EnableChildGatingComplete>(completionHandler)).toOpaque())
        }
    }

    public func disableChildGating(_ completionHandler: @escaping DisableChildGatingComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_session_disable_child_gating(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<DisableChildGatingComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_session_disable_child_gating_finish(OpaquePointer(source), result, &rawError)
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
            }, Unmanaged.passRetained(AsyncOperation<DisableChildGatingComplete>(completionHandler)).toOpaque())
        }
    }

    public func createScript(_ source: String, name: String? = nil, runtime: ScriptRuntime? = nil, completionHandler: @escaping CreateScriptComplete) {
        Runtime.scheduleOnFridaThread {
            let options = Session.parseScriptOptions(name, runtime)
            defer {
                g_object_unref(gpointer(options))
            }

            frida_session_create_script(self.handle, source, options, nil, { source, result, data in
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

    public func createScript(_ bytes: Data, name: String? = nil, runtime: ScriptRuntime? = nil, completionHandler: @escaping CreateScriptComplete) {
        Runtime.scheduleOnFridaThread {
            let rawBytes = Marshal.bytesFromData(bytes)
            let options = Session.parseScriptOptions(name, runtime)
            defer {
                g_object_unref(gpointer(options))
                g_bytes_unref(rawBytes)
            }

            frida_session_create_script_from_bytes(self.handle, rawBytes, options, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<CreateScriptComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawScript = frida_session_create_script_from_bytes_finish(OpaquePointer(source), result, &rawError)
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

    public func compileScript(_ source: String, name: String? = nil, runtime: ScriptRuntime? = nil, completionHandler: @escaping CompileScriptComplete) {
        Runtime.scheduleOnFridaThread {
            let options = Session.parseScriptOptions(name, runtime)
            defer {
                g_object_unref(gpointer(options))
            }

            frida_session_compile_script(self.handle, source, options, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<CompileScriptComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawBytes = frida_session_compile_script_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let bytes = Marshal.dataFromBytes(rawBytes!)

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { bytes }
                }
            }, Unmanaged.passRetained(AsyncOperation<CompileScriptComplete>(completionHandler)).toOpaque())
        }
    }

    private static func parseScriptOptions(_ name: String?, _ runtime: ScriptRuntime?) -> OpaquePointer {
        let options = frida_script_options_new()!

        if let name = name {
            frida_script_options_set_name(options, name)
        }

        if let runtime = runtime {
            frida_script_options_set_runtime(options, FridaScriptRuntime(runtime.rawValue))
        }

        return options
    }

    public func setupPeerConnection(stunServer: String? = nil, relays: [Relay]? = nil,
                                    completionHandler: @escaping SetupPeerConnectionComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            let options = frida_peer_options_new()
            defer {
                g_object_unref(gpointer(options))
            }

            if let stunServer = stunServer {
                frida_peer_options_set_stun_server(options, stunServer)
            }

            for relay in relays ?? [] {
                frida_peer_options_add_relay(options, relay.handle)
            }

            frida_session_setup_peer_connection(self.handle, options, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<SetupPeerConnectionComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_session_setup_peer_connection_finish(OpaquePointer(source), result, &rawError)
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
            }, Unmanaged.passRetained(AsyncOperation<SetupPeerConnectionComplete>(completionHandler)).toOpaque())
        }
    }

    public func joinPortal(_ address: String, certificate: String? = nil, token: String? = nil, acl: [String]? = nil,
                           completionHandler: @escaping JoinPortalComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            let options = frida_portal_options_new()
            defer {
                g_object_unref(gpointer(options))
            }

            if let certificate = certificate {
                do {
                    let rawCertificate = try Marshal.certificateFromString(certificate)
                    frida_portal_options_set_certificate(options, rawCertificate)
                    g_object_unref(rawCertificate)
                } catch let error {
                    Runtime.scheduleOnMainThread {
                        completionHandler { throw error }
                    }
                    return
                }
            }

            if let token = token {
                frida_portal_options_set_token(options, token)
            }

            let (rawAcl, aclLength) = Marshal.strvFromArray(acl)
            if let rawAcl = rawAcl {
                frida_portal_options_set_acl(options, rawAcl, aclLength)
                g_strfreev(rawAcl)
            }

            frida_session_join_portal(self.handle, address, options, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<JoinPortalComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawMembership = frida_session_join_portal_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let membership = PortalMembership(handle: rawMembership!)

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { membership }
                }
            }, Unmanaged.passRetained(AsyncOperation<JoinPortalComplete>(completionHandler)).toOpaque())
        }
    }

    private let onDetached: DetachedHandler = { _, reason, rawCrash, userData in
        let connection = Unmanaged<SignalConnection<Session>>.fromOpaque(userData).takeUnretainedValue()

        var crash: CrashDetails? = nil
        if let rawCrash = rawCrash {
            g_object_ref(gpointer(rawCrash))
            crash = CrashDetails(handle: rawCrash)
        }

        if let session = connection.instance {
            Runtime.scheduleOnMainThread {
                session.delegate?.session(session, didDetach: SessionDetachReason(rawValue: reason)!, crash: crash)
            }
        }
    }

    private let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<Session>>.fromOpaque(data!).release()
    }
}

@objc(FridaSessionDetachReason)
public enum SessionDetachReason: Int, CustomStringConvertible {
    case applicationRequested = 1
    case processReplaced
    case processTerminated
    case connectionTerminated
    case deviceLost

    public var description: String {
        switch self {
        case .applicationRequested: return "applicationRequested"
        case .processReplaced: return "processReplaced"
        case .processTerminated: return "processTerminated"
        case .connectionTerminated: return "connectionTerminated"
        case .deviceLost: return "deviceLost"
        }
    }
}

@objc(FridaScriptRuntime)
public enum ScriptRuntime: UInt32, CustomStringConvertible {
    case auto
    case qjs
    case v8

    public var description: String {
        switch self {
        case .auto: return "auto"
        case .qjs: return "qjs"
        case .v8: return "v8"
        }
    }
}
