import Frida_Private

public final class Script: CustomStringConvertible, Equatable, Hashable {
    public weak var delegate: (any ScriptDelegate)?

    private typealias DestroyHandler = @convention(c) (_ script: OpaquePointer, _ userData: gpointer) -> Void
    private typealias MessageHandler = @convention(c) (_ script: OpaquePointer, _ json: UnsafePointer<gchar>,
        _ data: OpaquePointer?, _ userData: gpointer) -> Void

    private let handle: OpaquePointer

    private var rpcContinuations: [Int: (RpcInternalResult) -> Void] = [:]
    private var requestId = 0

    init(handle: OpaquePointer) {
        self.handle = handle

        let rawHandle = gpointer(handle)
        g_signal_connect_data(rawHandle, "destroyed", unsafeBitCast(onDestroyed, to: GCallback.self),
                              gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                              releaseConnection, GConnectFlags(0))
        g_signal_connect_data(rawHandle, "message", unsafeBitCast(onMessage, to: GCallback.self),
                              gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                              releaseConnection, GConnectFlags(0))
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public lazy var exports: Exports = {
        return Exports(script: self)
    }()

    public var description: String {
        return "Frida.Script()"
    }

    public static func == (lhs: Script, rhs: Script) -> Bool {
        return lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }

    public func load() async throws {
        return try await fridaAsync(Void.self) { op in
            frida_script_load(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_script_load_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func unload() async throws {
        return try await fridaAsync(Void.self) { op in
            frida_script_unload(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_script_unload_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func eternalize() async throws {
        return try await fridaAsync(Void.self) { op in
            frida_script_eternalize(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_script_eternalize_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func post(_ message: Any, data: [UInt8]? = nil) {
        let json = Marshal.jsonFromValue(message)
        let rawData = Marshal.bytesFromArray(data)

        frida_script_post(handle, json, rawData)

        g_bytes_unref(rawData)
    }

    public func enableDebugger(_ port: UInt16 = 0) async throws {
        return try await fridaAsync(Void.self) { op in
            frida_script_enable_debugger(self.handle, port, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_script_enable_debugger_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func disableDebugger() async throws {
        return try await fridaAsync(Void.self) { op in
            frida_script_disable_debugger(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_script_disable_debugger_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    private let onDestroyed: DestroyHandler = { _, userData in
        let connection = Unmanaged<SignalConnection<Script>>.fromOpaque(userData).takeUnretainedValue()

        if let script = connection.instance {
            script.failAllRpcContinuations(Error.rpcError(
                message: "Script destroyed",
                stackTrace: nil
            ))

            Runtime.scheduleOnMainThread {
                script.delegate?.scriptDestroyed(script)
            }
        }
    }

    private let onMessage: MessageHandler = { _, rawJson, rawData, userData in
        let connection = Unmanaged<SignalConnection<Script>>.fromOpaque(userData).takeUnretainedValue()

        guard let script = connection.instance else { return }

        let jsonString = Marshal.stringFromCString(rawJson)
        let parsedAny = Marshal.valueFromJSON(jsonString)
        let dataBytes = Marshal.arrayFromBytes(rawData)

        guard
            let msgDict = parsedAny as? [String: Any],
            let payloadAny = msgDict["payload"],
            let payload = payloadAny as? [Any],
            payload.count >= 3,
            let kind = payload[0] as? String,
            kind == "frida:rpc",
            let requestId = payload[1] as? Int,
            let status = payload[2] as? String
        else {
            Runtime.scheduleOnMainThread {
                script.delegate?.script(script,
                                        didReceiveMessage: parsedAny,
                                        withData: dataBytes)
            }
            return
        }

        guard let cont = script.rpcContinuations[requestId] else {
            return
        }
        script.rpcContinuations[requestId] = nil

        if status == "ok" {
            var result: Any? = nil
            if let db = dataBytes {
                result = db
            } else if payload.count >= 4 {
                result = payload[3]
            }
            cont(.success(value: result))
        } else {
            let message = (payload.count >= 4 ? (payload[3] as? String ?? "") : "")
            let stackTrace = (payload.count >= 6 ? payload[5] as? String : nil)
            cont(.error(Error.rpcError(message: message, stackTrace: stackTrace)))
        }
    }

    private let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<Script>>.fromOpaque(data!).release()
    }

    // MARK: - RPC

    @dynamicMemberLookup
    public struct Exports {
        unowned let script: Script

        init(script: Script) {
            self.script = script
        }

        public subscript(dynamicMember functionName: String) -> RpcFunction {
            get {
                return RpcFunction(script: self.script, functionName: functionName)
            }
        }
    }

    internal func rpcCall(functionName: String, args: [Any]) async throws -> Any? {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Any?, Swift.Error>) in
            Runtime.scheduleOnFridaThread { [weak self] in
                guard let self else {
                    cont.resume(throwing: Error.rpcError(
                        message: "Script deallocated before RPC could be scheduled",
                        stackTrace: nil
                    ))
                    return
                }

                let id = self.requestId
                self.requestId &+= 1

                let message: [Any] = [
                    String(describing: FridaRpcKind.default),
                    id,
                    String(describing: FridaRpcOperation.call),
                    functionName,
                    args
                ]

                self.rpcContinuations[id] = { result in
                    switch result {
                    case let .success(value):
                        cont.resume(returning: value)
                    case let .error(error):
                        cont.resume(throwing: error)
                    }
                }

                self.post(message)
            }
        }
    }

    private func failAllRpcContinuations(_ error: Swift.Error) {
        let pending = rpcContinuations.values
        rpcContinuations.removeAll()

        for cont in pending {
            cont(.error(error))
        }
    }

    func makeRequestId() -> Int {
        let currentId = requestId
        requestId += 1
        return currentId
    }

    // MARK: - Private Types

    private enum FridaMessageType: String, Decodable {
        case error
        case log
        case send
    }

    private enum FridaRpcKind: String, Decodable, CustomStringConvertible {
        case `default` = "frida:rpc"

        var description: String {
            return rawValue
        }
    }

    private enum FridaRpcStatus: String, Decodable {
        case ok
        case error
    }

    private enum FridaRpcOperation: String, CustomStringConvertible {
        case call

        var description: String {
            return rawValue
        }
    }

    private struct FridaRpcPayload: Decodable {
        let kind: FridaRpcKind
        let requestId: Int
        let status: FridaRpcStatus

        init(from decoder: Decoder) throws{
            var container = try decoder.unkeyedContainer()
            kind = try container.decode(FridaRpcKind.self)
            requestId = try container.decode(Int.self)
            status = try container.decode(FridaRpcStatus.self)
        }
    }

    internal enum RpcInternalResult {
        case success(value: Any?)
        case error(Swift.Error)
    }
}
