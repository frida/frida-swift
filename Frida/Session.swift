import FridaCore

public final class Session: @unchecked Sendable, CustomStringConvertible, Equatable, Hashable {
    public var events: Events {
        eventSource.makeStream()
    }

    public typealias Events = AsyncStream<Event>

    @frozen
    public enum Event {
        case detached(reason: SessionDetachReason, crash: CrashDetails?)
    }

    private let handle: OpaquePointer
    private let eventSource = AsyncEventSource<Event>()

    init(handle: OpaquePointer) {
        self.handle = handle

        connectSignal(instance: self, handle: handle, signal: "detached", handler: onDetached)
    }

    deinit {
        eventSource.finish()
        g_object_unref(gpointer(handle))
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

    public var description: String {
        return "Frida.Session(pid: \(pid))"
    }

    public static func == (lhs: Session, rhs: Session) -> Bool {
        return lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }

    public func detach() async throws {
        try await fridaAsync(Void.self) { op in
            frida_session_detach(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_session_detach_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func resume() async throws {
        return try await fridaAsync(Void.self) { op in
            frida_session_resume(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_session_resume_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func enableChildGating() async throws {
        return try await fridaAsync(Void.self) { op in
            frida_session_enable_child_gating(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_session_enable_child_gating_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func disableChildGating() async throws {
        return try await fridaAsync(Void.self) { op in
            frida_session_disable_child_gating(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_session_disable_child_gating_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func createScript(_ source: String, name: String? = nil, runtime: ScriptRuntime? = nil) async throws -> Script {
        return try await fridaAsync(Script.self) { op in
            let options = Session.parseScriptOptions(name, runtime)

            frida_session_create_script(self.handle, source, options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Script>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawScript = frida_session_create_script_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                let script = Script(handle: rawScript!)
                op.resumeSuccess(script)
            }, op.userData)

            g_object_unref(gpointer(options))
        }
    }

    public func createScript(_ bytes: [UInt8], name: String? = nil, runtime: ScriptRuntime? = nil) async throws -> Script {
        return try await fridaAsync(Script.self) { op in
            let rawBytes = Marshal.bytesFromArray(bytes)
            let options = Session.parseScriptOptions(name, runtime)

            frida_session_create_script_from_bytes(self.handle, rawBytes, options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Script>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawScript = frida_session_create_script_from_bytes_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                let script = Script(handle: rawScript!)
                op.resumeSuccess(script)
            }, op.userData)

            g_object_unref(gpointer(options))
            g_bytes_unref(rawBytes)
        }
    }

    public func compileScript(_ source: String, name: String? = nil, runtime: ScriptRuntime? = nil) async throws -> [UInt8] {
        return try await fridaAsync([UInt8].self) { op in
            let options = Session.parseScriptOptions(name, runtime)

            frida_session_compile_script(self.handle, source, options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<[UInt8]>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawBytes = frida_session_compile_script_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(Marshal.arrayFromBytes(rawBytes)!)

                g_bytes_unref(rawBytes)
            }, op.userData)

            g_object_unref(gpointer(options))
        }
    }

    private static func parseScriptOptions(_ name: String?, _ runtime: ScriptRuntime?) -> OpaquePointer {
        let options = frida_script_options_new()!

        if let name {
            frida_script_options_set_name(options, name)
        }

        if let runtime {
            frida_script_options_set_runtime(options, FridaScriptRuntime(runtime.rawValue))
        }

        return options
    }

    public func setupPeerConnection(stunServer: String? = nil, relays: [Relay]? = nil) async throws {
        return try await fridaAsync(Void.self) { op in
            let options = frida_peer_options_new()

            if let stunServer {
                frida_peer_options_set_stun_server(options, stunServer)
            }

            for relay in relays ?? [] {
                frida_peer_options_add_relay(options, relay.handle)
            }

            frida_session_setup_peer_connection(self.handle, options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_session_setup_peer_connection_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)

            g_object_unref(gpointer(options))
        }
    }

    public func joinPortal(_ address: String, certificate: String? = nil, token: String? = nil, acl: [String]? = nil) async throws -> PortalMembership {
        let options = frida_portal_options_new()
        defer { g_object_unref(gpointer(options)) }

        if let certificate {
            let rawCertificate = try Marshal.certificateFromString(certificate)
            frida_portal_options_set_certificate(options, rawCertificate)
            g_object_unref(rawCertificate)
        }

        if let token {
            frida_portal_options_set_token(options, token)
        }

        let (rawAcl, aclLength) = Marshal.strvFromArray(acl)
        if let rawAcl = rawAcl {
            frida_portal_options_set_acl(options, rawAcl, aclLength)
            g_strfreev(rawAcl)
        }

        g_object_ref(gpointer(options))

        return try await fridaAsync(PortalMembership.self) { op in
            frida_session_join_portal(self.handle, address, options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<PortalMembership>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawMembership = frida_session_join_portal_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                let membership = PortalMembership(handle: rawMembership!)
                op.resumeSuccess(membership)
            }, op.userData)

            g_object_unref(gpointer(options))
        }
    }

    private let onDetached: @convention(c) (OpaquePointer, Int, OpaquePointer?, gpointer) -> Void = { _, reason, rawCrash, userData in
        let connection = Unmanaged<SignalConnection<Session>>.fromOpaque(userData).takeUnretainedValue()

        var crash: CrashDetails? = nil
        if let rawCrash = rawCrash {
            g_object_ref(gpointer(rawCrash))
            crash = CrashDetails(handle: rawCrash)
        }

        connection.instance?.eventSource.finish(replayLast: .detached(reason: SessionDetachReason(rawValue: reason)!, crash: crash))
    }

    private func publish(_ event: Event) {
        eventSource.yield(event)
    }
}

@frozen
public enum SessionDetachReason: Int, Codable, CustomStringConvertible {
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

@frozen
public enum ScriptRuntime: UInt32, Codable, CustomStringConvertible {
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
