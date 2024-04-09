import Foundation
import Frida_Private

@objc(FridaIOStream)
public class IOStream: NSObject, NSCopying {
    public typealias CloseComplete = (_ result: CloseResult) -> Void
    public typealias CloseResult = () throws -> Bool

    public typealias ReadComplete = (_ result: ReadResult) -> Void
    public typealias ReadResult = () throws -> Data

    public typealias ReadAllComplete = (_ result: ReadAllResult) -> Void
    public typealias ReadAllResult = () throws -> Data

    public typealias WriteComplete = (_ result: WriteResult) -> Void
    public typealias WriteResult = () throws -> UInt

    public typealias WriteAllComplete = (_ result: WriteAllResult) -> Void
    public typealias WriteAllResult = () throws -> Bool

    private let handle: UnsafeMutablePointer<GIOStream>
    private let input: UnsafeMutablePointer<GInputStream>
    private let output: UnsafeMutablePointer<GOutputStream>

    private let ioPriority: Int32 = 0

    init(handle: UnsafeMutablePointer<GIOStream>) {
        self.handle = handle
        input = g_io_stream_get_input_stream(handle)
        output = g_io_stream_get_output_stream(handle)

        super.init()
    }

    public func copy(with zone: NSZone?) -> Any {
        g_object_ref(gpointer(handle))
        return IOStream(handle: handle)
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var isClosed: Bool {
        return g_io_stream_is_closed(handle) != 0
    }

    public override var description: String {
        return "Frida.IOStream()"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        if let script = object as? IOStream {
            return script.handle == handle
        } else {
            return false
        }
    }

    public override var hash: Int {
        return handle.hashValue
    }

    public func close(_ count: UInt, completionHandler: @escaping CloseComplete) {
        Runtime.scheduleOnFridaThread {
            g_io_stream_close_async(self.handle, self.ioPriority, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<CloseComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                g_io_stream_close_finish(UnsafeMutablePointer<GIOStream>(OpaquePointer(source)), result, &rawError)
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
            }, Unmanaged.passRetained(AsyncOperation<CloseComplete>(completionHandler)).toOpaque())
        }
    }

    public func read(_ count: UInt, completionHandler: @escaping ReadComplete) {
        Runtime.scheduleOnFridaThread {
            g_input_stream_read_bytes_async(self.input, count, self.ioPriority, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<ReadComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let bytes = g_input_stream_read_bytes_finish(UnsafeMutablePointer<GInputStream>(OpaquePointer(source)), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let data = Marshal.dataFromBytes(bytes!)

                g_bytes_unref(bytes)

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { data }
                }
            }, Unmanaged.passRetained(AsyncOperation<ReadComplete>(completionHandler)).toOpaque())
        }
    }

    public func readAll(_ count: UInt, completionHandler: @escaping ReadAllComplete) {
        Runtime.scheduleOnFridaThread {
            let buffer = g_malloc(count)!
            g_input_stream_read_all_async(self.input, buffer, count, self.ioPriority, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<ReadAllComplete>>.fromOpaque(data!).takeRetainedValue()

                let buffer = operation.userData!
                defer {
                    g_free(buffer)
                }

                var numBytesReadAll: gsize = 0
                var rawError: UnsafeMutablePointer<GError>? = nil
                g_input_stream_read_all_finish(UnsafeMutablePointer<GInputStream>(OpaquePointer(source)), result, &numBytesReadAll, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let data = Data(bytes: buffer, count: Int(numBytesReadAll))

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { data }
                }
            }, Unmanaged.passRetained(AsyncOperation<ReadAllComplete>(completionHandler, userData: buffer)).toOpaque())
        }
    }

    public func write(_ data: Data, completionHandler: @escaping WriteComplete) {
        Runtime.scheduleOnFridaThread {
            let bytes = Marshal.bytesFromData(data)
            g_output_stream_write_bytes_async(self.output, bytes, self.ioPriority, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<WriteComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let numBytesWritten = g_output_stream_write_bytes_finish(UnsafeMutablePointer<GOutputStream>(OpaquePointer(source)), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { UInt(numBytesWritten) }
                }
            }, Unmanaged.passRetained(AsyncOperation<WriteComplete>(completionHandler)).toOpaque())
            g_bytes_unref(bytes)
        }
    }

    public func writeAll(_ data: Data, completionHandler: @escaping WriteAllComplete) {
        Runtime.scheduleOnFridaThread {
            let buffer = data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
                return g_memdup2(ptr.baseAddress, gsize(ptr.count))
            }
            g_output_stream_write_all_async(self.output, buffer, gsize(data.count), self.ioPriority, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<WriteAllComplete>>.fromOpaque(data!).takeRetainedValue()

                let buffer = operation.userData!
                defer {
                    g_free(buffer)
                }

                var numBytesWritten: gsize = 0
                var rawError: UnsafeMutablePointer<GError>? = nil
                g_output_stream_write_all_finish(UnsafeMutablePointer<GOutputStream>(OpaquePointer(source)), result, &numBytesWritten, &rawError)
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
            }, Unmanaged.passRetained(AsyncOperation<WriteAllComplete>(completionHandler, userData: buffer)).toOpaque())
        }
    }
}
