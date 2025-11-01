import Foundation
import Frida_Private

@objc(FridaScript)
public class Script: NSObject, NSCopying {
    public weak var delegate: ScriptDelegate?

    private typealias DestroyHandler = @convention(c) (_ script: OpaquePointer, _ userData: gpointer) -> Void
    private typealias MessageHandler = @convention(c) (_ script: OpaquePointer, _ json: UnsafePointer<gchar>,
        _ data: OpaquePointer?, _ userData: gpointer) -> Void

    private let handle: OpaquePointer
    private var onDestroyedHandler: gulong = 0
    private var onMessageHandler: gulong = 0

    init(handle: OpaquePointer) {
        self.handle = handle

        super.init()

        let rawHandle = gpointer(handle)
        onDestroyedHandler = g_signal_connect_data(rawHandle, "destroyed", unsafeBitCast(onDestroyed, to: GCallback.self),
                                                   gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                   releaseConnection, GConnectFlags(0))
        onMessageHandler = g_signal_connect_data(rawHandle, "message", unsafeBitCast(onMessage, to: GCallback.self),
                                                 gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                 releaseConnection, GConnectFlags(0))
    }

    public func copy(with zone: NSZone?) -> Any {
        g_object_ref(gpointer(handle))
        return Script(handle: handle)
    }

    deinit {
        let rawHandle = gpointer(handle)
        let handlers = [onDestroyedHandler, onMessageHandler]
        Runtime.scheduleOnFridaThread {
            for handler in handlers {
                g_signal_handler_disconnect(rawHandle, handler)
            }
            g_object_unref(rawHandle)
        }
    }

    public lazy var exports: Exports = {
        return Exports(script: self)
    }()

    public override var description: String {
        return "Frida.Script()"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        if let script = object as? Script {
            return script.handle == handle
        } else {
            return false
        }
    }

    public override var hash: Int {
        return handle.hashValue
    }

    @MainActor
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

    @MainActor
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

    @MainActor
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

    public func post(_ message: Any, data: Data? = nil) {
        let jsonData = try! JSONSerialization.data(withJSONObject: message, options: [])
        let json = String(data: jsonData, encoding: .utf8)!

        let rawData = Marshal.bytesFromData(data)
        frida_script_post(handle, json, rawData)
        g_bytes_unref(rawData)
    }

    @MainActor
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

    @MainActor
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
            Runtime.scheduleOnMainThread {
                script.delegate?.scriptDestroyed?(script)
            }
        }
    }

    private let onMessage: MessageHandler = { _, rawJson, rawData, userData in
        let connection = Unmanaged<SignalConnection<Script>>.fromOpaque(userData).takeUnretainedValue()

        let json = Data(bytesNoCopy: UnsafeMutableRawPointer.init(mutating: rawJson), count: Int(strlen(rawJson)), deallocator: .none)
        let message = try! JSONSerialization.jsonObject(with: json, options: JSONSerialization.ReadingOptions())

        let data = Marshal.dataFromBytes(rawData)

        let decoder = JSONDecoder()
        do {
            let rpcMessage = try decoder.decode(FridaRpcMessage.self, from: json)
            let script = connection.instance!
            let messageDict = message as! [String: Any]
            let payload = messageDict[FridaRpcMessage.CodingKeys.payload.rawValue] as! [Any]
            let callback = script.rpcCallbacks[rpcMessage.payload.requestId]!

            if rpcMessage.payload.status == .ok {
                var result: Any?
                if let data = data {
                    result = data
                } else {
                    result = payload[3]
                }

                callback(.success(value: result))
            } else {
                let errorMessage = payload[3] as! String
                var stackTraceMaybe: String?
                if payload.count >= 6 {
                    stackTraceMaybe = (payload[5] as! String)
                }

                let error = Error.rpcError(message: errorMessage, stackTrace: stackTraceMaybe)
                callback(.error(error))
            }

            script.rpcCallbacks.removeValue(forKey: rpcMessage.payload.requestId)
            return
        } catch {}

        if let script = connection.instance {
            Runtime.scheduleOnMainThread {
                script.delegate?.script?(script, didReceiveMessage: message, withData: data)
            }
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

    internal typealias RpcInternalResultCallback = (_ result: RpcInternalResult) -> Void
    private var rpcCallbacks: [Int: RpcInternalResultCallback] = [:]
    private var requestId = 0
    var nextRequestId: Int {
        get {
            let currentId = requestId
            requestId += 1
            return currentId
        }
    }

    internal func rpcPost(functionName: String, requestId: Int, values: [Any]) -> RpcRequest {
        let message: [Any] = [
            String(describing: FridaRpcKind.default),
            requestId,
            String(describing: FridaRpcOperation.call),
            functionName,
            values
        ]

        let request = RpcRequest()
        rpcCallbacks[requestId] = { result in
            request.received(result: result)
        }

        post(message, data: nil)

        return request
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

    private struct FridaRpcMessage: Decodable {
        let type: FridaMessageType
        let payload: FridaRpcPayload

        enum CodingKeys: String, CodingKey {
            case type
            case payload
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
}
