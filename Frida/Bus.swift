import CFrida
import Foundation

@objc(FridaBus)
public class Bus: NSObject, NSCopying {
    public weak var delegate: BusDelegate?

    public typealias AttachComplete = (_ result: AttachResult) -> Void
    public typealias AttachResult = () throws -> Bool

    private typealias DetachHandler = @convention(c) (_ bus: OpaquePointer, _ userData: gpointer) -> Void
    private typealias MessageHandler = @convention(c) (_ bus: OpaquePointer, _ json: UnsafePointer<gchar>,
        _ data: OpaquePointer?, _ userData: gpointer) -> Void

    private let handle: OpaquePointer
    private var onDetachedHandler: gulong = 0
    private var onMessageHandler: gulong = 0

    init(handle: OpaquePointer) {
        self.handle = handle

        super.init()

        let rawHandle = gpointer(handle)
        onDetachedHandler = g_signal_connect_data(rawHandle, "detached", unsafeBitCast(onDetached, to: GCallback.self),
                                                   gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                   releaseConnection, GConnectFlags(0))
        onMessageHandler = g_signal_connect_data(rawHandle, "message", unsafeBitCast(onMessage, to: GCallback.self),
                                                 gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                 releaseConnection, GConnectFlags(0))
    }

    public func copy(with zone: NSZone?) -> Any {
        g_object_ref(gpointer(handle))
        return Bus(handle: handle)
    }

    deinit {
        let rawHandle = gpointer(handle)
        let handlers = [onDetachedHandler, onMessageHandler]
        Runtime.scheduleOnFridaThread {
            for handler in handlers {
                g_signal_handler_disconnect(rawHandle, handler)
            }
            g_object_unref(rawHandle)
        }
    }

    public var isClosed: Bool {
        return frida_bus_is_detached(handle) != 0
    }

    public override var description: String {
        return "Frida.Bus()"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        if let bus = object as? Bus {
            return bus.handle == handle
        } else {
            return false
        }
    }

    public override var hash: Int {
        return handle.hashValue
    }

    public func attach(_ completionHandler: @escaping AttachComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_bus_attach(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<AttachComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_bus_attach_finish(OpaquePointer(source), result, &rawError)
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
            }, Unmanaged.passRetained(AsyncOperation<AttachComplete>(completionHandler)).toOpaque())
        }
    }

    public func post(_ message: Any, data: Data? = nil) {
        let jsonData = try! JSONSerialization.data(withJSONObject: message, options: JSONSerialization.WritingOptions())
        let json = String(data: jsonData, encoding: String.Encoding.utf8)!

        let rawData = Marshal.bytesFromData(data)

        frida_bus_post(handle, json, rawData)

        g_bytes_unref(rawData)
    }

    private let onDetached: DetachHandler = { _, userData in
        let connection = Unmanaged<SignalConnection<Bus>>.fromOpaque(userData).takeUnretainedValue()

        if let bus = connection.instance {
            Runtime.scheduleOnMainThread {
                bus.delegate?.busDetached?(bus)
            }
        }
    }

    private let onMessage: MessageHandler = { _, rawJson, rawData, userData in
        let connection = Unmanaged<SignalConnection<Bus>>.fromOpaque(userData).takeUnretainedValue()

        let json = Data(bytesNoCopy: UnsafeMutableRawPointer.init(mutating: rawJson), count: Int(strlen(rawJson)), deallocator: .none)
        let message = try! JSONSerialization.jsonObject(with: json, options: JSONSerialization.ReadingOptions())

        let data = Marshal.dataFromBytes(rawData)

        if let bus = connection.instance {
            Runtime.scheduleOnMainThread {
                bus.delegate?.bus?(bus, didReceiveMessage: message, withData: data)
            }
        }
    }

    private let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<Bus>>.fromOpaque(data!).release()
    }
}
