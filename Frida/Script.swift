import CFrida

@objc(FridaScript)
public class Script: NSObject, NSCopying {
    public weak var delegate: ScriptDelegate?

    public typealias LoadComplete = (_ result: LoadResult) -> Void
    public typealias LoadResult = () throws -> Bool

    public typealias UnloadComplete = (_ result: UnloadResult) -> Void
    public typealias UnloadResult = () throws -> Bool

    public typealias EternalizeComplete = (_ result: EternalizeResult) -> Void
    public typealias EternalizeResult = () throws -> Bool

    public typealias PostComplete = (_ result: PostResult) -> Void
    public typealias PostResult = () throws -> Bool

    private typealias DestroyHandler = @convention(c) (_ script: OpaquePointer, _ userData: gpointer) -> Void
    private typealias MessageHandler = @convention(c) (_ script: OpaquePointer, _ message: UnsafePointer<gchar>,
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

    public func load(_ completionHandler: @escaping LoadComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_script_load(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<LoadComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_script_load_finish(OpaquePointer(source), result, &rawError)
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
            }, Unmanaged.passRetained(AsyncOperation<LoadComplete>(completionHandler)).toOpaque())
        }
    }

    public func unload(_ completionHandler: @escaping UnloadComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_script_unload(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<UnloadComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_script_unload_finish(OpaquePointer(source), result, &rawError)
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
            }, Unmanaged.passRetained(AsyncOperation<UnloadComplete>(completionHandler)).toOpaque())
        }
    }

    public func eternalize(_ completionHandler: @escaping EternalizeComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_script_eternalize(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EternalizeComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_script_eternalize_finish(OpaquePointer(source), result, &rawError)
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
            }, Unmanaged.passRetained(AsyncOperation<EternalizeComplete>(completionHandler)).toOpaque())
        }
    }

    public func post(_ message: Any, data: Data? = nil, completionHandler: @escaping PostComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            let operation = AsyncOperation<PostComplete>(completionHandler)

            var rawMessage: String
            do {
                let data = try JSONSerialization.data(withJSONObject: message, options: JSONSerialization.WritingOptions())
                rawMessage = String(data: data, encoding: String.Encoding.utf8)!
            } catch {
                Runtime.scheduleOnMainThread {
                    operation.completionHandler { throw error }
                }
                return;
            }

            let rawData = Bytes.fromData(buffer: data)

            frida_script_post(self.handle, rawMessage, rawData, { source, result, data in
                let operation = Unmanaged<AsyncOperation<PostComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_script_post_finish(OpaquePointer(source), result, &rawError)
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
            }, Unmanaged.passRetained(operation).toOpaque())

            g_bytes_unref(rawData)
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
    
    // MARK: - Message Handling

    enum FridaMessageType: String, Decodable {
        case error
        case log
        case send
    }
    
    enum FridaRpcKind: String, Decodable {
        case fridaRpc = "frida:rpc"
    }
    
    struct FridaRpcMessage: Decodable {
        let type: FridaMessageType
        let payload: FridaRpcPayload
    }
    
    struct FridaRpcPayload: Decodable {
        let kind: FridaRpcKind
        let requestId: Int
        let success: String
        
        init(from decoder: Decoder) throws{
            var container = try decoder.unkeyedContainer()
            kind = try container.decode(FridaRpcKind.self)
            requestId = try container.decode(Int.self)
            success = try container.decode(String.self)
        }
    }
    
    private let onMessage: MessageHandler = { _, rawMessage, rawData, userData in
        let connection = Unmanaged<SignalConnection<Script>>.fromOpaque(userData).takeUnretainedValue()

        let messageData = Data(bytesNoCopy: UnsafeMutableRawPointer.init(mutating: rawMessage), count: Int(strlen(rawMessage)), deallocator: .none)
        let message = try! JSONSerialization.jsonObject(with: messageData, options: JSONSerialization.ReadingOptions())
        
        var data: Data? = nil
        if let rawData = rawData {
            var size: gsize = 0
            if let rawDataBytes = g_bytes_get_data(rawData, &size), size > 0 {
                g_bytes_ref(rawData)
                data = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: rawDataBytes), count: Int(size), deallocator: .custom({ (ptr, size) in
                    g_bytes_unref(rawData)
                }))
            } else {
                data = Data()
            }
        }

        let decoder = JSONDecoder()
        do {
            let rpcMessage = try decoder.decode(FridaRpcMessage.self, from: messageData)
            let script = connection.instance!
            let payload = (message as! [String: Any])["payload"] as! [Any]
            let callback = script.rpcCallbacks[rpcMessage.payload.requestId]!
            if rpcMessage.payload.success == "ok" {
                var result: Any?
                if let data = data {
                    result = data
                } else {
                    result = payload[3]
                }
                callback(.success(value: result))
            }
            else {
                let error = rpcMessage.payload.success
                callback(.error(error: error))
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
    
    // MARK: - RPC Types
    
    @dynamicMemberLookup
    public struct Exports {
        unowned let script: Script
        
        init(script: Script) {
            self.script = script
        }
        
        subscript(dynamicMember functionName: String) -> RpcFunction {
            get {
                return RpcFunction(script: self.script, functionName: functionName)
            }
        }
    }
    
    // MARK: - RPC
    
    public lazy var exports: Exports = {
        return Exports(script: self)
    }()
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
    
    internal func rpcPost(functionName: String, requestId: Int, values: [Any]) throws -> RpcRequest {
        let message: [Any] = [
            "frida:rpc",
            requestId,
            "call",
            functionName,
            values
        ]
        
        let request = RpcRequest()
        rpcCallbacks[requestId] = { result in
            request.received(result: result)
        }
        
        post(message, data: nil) { result in
            do {
                let _ = try result()
            } catch let error {
                request.received(result: .error(error: error.localizedDescription))
            }
        }

        return request
    }
}
