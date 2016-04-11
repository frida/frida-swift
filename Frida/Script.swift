import CFrida

@objc(FridaScript)
public class Script: NSObject, NSCopying {
    public weak var delegate: ScriptDelegate?

    public typealias LoadComplete = (result: LoadResult) -> Void
    public typealias LoadResult = () throws -> Bool

    public typealias UnloadComplete = (result: UnloadResult) -> Void
    public typealias UnloadResult = () throws -> Bool

    public typealias PostMessageComplete = (result: PostMessageResult) -> Void
    public typealias PostMessageResult = () throws -> Bool

    private typealias DestroyHandler = @convention(c) (script: COpaquePointer, userData: gpointer) -> Void
    private typealias MessageHandler = @convention(c) (script: COpaquePointer, message: UnsafePointer<gchar>,
        data: UnsafePointer<guint8>, dataSize: gint, userData: gpointer) -> Void

    private let handle: COpaquePointer
    private var onDestroyedHandler: gulong = 0
    private var onMessageHandler: gulong = 0

    init(handle: COpaquePointer) {
        self.handle = handle

        super.init()

        let rawHandle = gpointer(handle)
        onDestroyedHandler = g_signal_connect_data(rawHandle, "destroyed", unsafeBitCast(onDestroyed, GCallback.self),
                                                   gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                   releaseConnection, GConnectFlags(0))
        onMessageHandler = g_signal_connect_data(rawHandle, "message", unsafeBitCast(onMessage, GCallback.self),
                                                 gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                 releaseConnection, GConnectFlags(0))
    }

    public func copyWithZone(zone: NSZone) -> AnyObject {
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

    public override func isEqual(object: AnyObject?) -> Bool {
        if let script = object as? Script {
            return script.handle == handle
        } else {
            return false
        }
    }

    public override var hash: Int {
        return handle.hashValue
    }

    public func load(completionHandler: LoadComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_script_load(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<LoadComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                frida_script_load_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<LoadComplete>(completionHandler)).toOpaque()))
        }
    }

    public func unload(completionHandler: UnloadComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_script_unload(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<UnloadComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                frida_script_unload_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<UnloadComplete>(completionHandler)).toOpaque()))
        }
    }

    public func postMessage(message: AnyObject, completionHandler: PostMessageComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            let operation = AsyncOperation<PostMessageComplete>(completionHandler)

            var rawMessage: String
            do {
                let data = try NSJSONSerialization.dataWithJSONObject(message, options: NSJSONWritingOptions())
                rawMessage = String(data: data, encoding: NSUTF8StringEncoding)!
            } catch {
                Runtime.scheduleOnMainThread {
                    operation.completionHandler { throw error }
                }
                return;
            }

            frida_script_post_message(self.handle, rawMessage, { source, result, data in
                let operation = Unmanaged<AsyncOperation<PostMessageComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                frida_script_post_message_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(operation).toOpaque()))
        }
    }

    private let onDestroyed: DestroyHandler = { _, userData in
        let connection = Unmanaged<SignalConnection<Script>>.fromOpaque(COpaquePointer(userData)).takeUnretainedValue()

        if let script = connection.instance {
            Runtime.scheduleOnMainThread {
                script.delegate?.scriptDestroyed?(script)
            }
        }
    }

    private let onMessage: MessageHandler = { _, rawMessage, rawData, rawDataSize, userData in
        let connection = Unmanaged<SignalConnection<Script>>.fromOpaque(COpaquePointer(userData)).takeUnretainedValue()

        let messageData = NSData(bytesNoCopy: UnsafeMutablePointer<Void>(rawMessage), length: Int(strlen(rawMessage)), freeWhenDone: false)
        let message = try! NSJSONSerialization.JSONObjectWithData(messageData, options: NSJSONReadingOptions())
        let data = NSData(bytes: rawData, length: Int(rawDataSize))

        if let script = connection.instance {
            Runtime.scheduleOnMainThread {
                script.delegate?.script?(script, didReceiveMessage: message, withData: data)
            }
        }
    }

    private let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<Script>>.fromOpaque(COpaquePointer(data)).release()
    }
}
