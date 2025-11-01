import Foundation
import Frida_Private

@objc(FridaIOStream)
public class IOStream: NSObject, NSCopying {
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

    @MainActor
    public func close(_ count: UInt) async throws {
        try await fridaAsync(Void.self) { op in
            let userData = op.userData

            g_io_stream_close_async(self.handle, self.ioPriority, op.cancellable, { sourcePtr, asyncResultPtr, userDataPtr in
                let op = InternalOp<Void>.takeRetained(from: userDataPtr!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                g_io_stream_close_finish(UnsafeMutablePointer<GIOStream>(OpaquePointer(sourcePtr)), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, userData)
        }
    }

    @MainActor
    public func read(_ count: UInt) async throws -> Data {
        try await fridaAsync(Data.self) { op in
            let userData = op.userData

            g_input_stream_read_bytes_async(self.input, count, self.ioPriority, op.cancellable, { sourcePtr, asyncResultPtr, userDataPtr in
                let op = InternalOp<Data>.takeRetained(from: userDataPtr!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let bytes = g_input_stream_read_bytes_finish(UnsafeMutablePointer<GInputStream>(OpaquePointer(sourcePtr)), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(Marshal.dataFromBytes(bytes!))

                g_bytes_unref(bytes)
            }, userData)
        }
    }

    @MainActor
    public func readAll(_ count: UInt) async throws -> Data {
        try await fridaAsync(Data.self) { op in
            let buffer = g_malloc(count)!
            op.payload = buffer
            let userData = op.userData

            g_input_stream_read_all_async(self.input, buffer, count, self.ioPriority, op.cancellable, { sourcePtr, asyncResultPtr, userDataPtr in
                let op = InternalOp<Data>.takeRetained(from: userDataPtr!)

                let buffer = op.payload!
                op.payload = nil
                defer { g_free(buffer) }

                var bytesRead: gsize = 0
                var rawError: UnsafeMutablePointer<GError>? = nil
                g_input_stream_read_all_finish(UnsafeMutablePointer<GInputStream>(OpaquePointer(sourcePtr)), asyncResultPtr, &bytesRead, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(Data(bytes: buffer, count: Int(bytesRead)))
            }, userData)
        }
    }

    @MainActor
    public func write(_ data: Data) async throws -> UInt {
        try await fridaAsync(UInt.self) { op in
            let bytes = Marshal.bytesFromData(data)
            let userData = op.userData

            g_output_stream_write_bytes_async(self.output, bytes, self.ioPriority, op.cancellable, { sourcePtr, asyncResultPtr, userDataPtr in
                let op = InternalOp<UInt>.takeRetained(from: userDataPtr!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let numBytesWritten = g_output_stream_write_bytes_finish(UnsafeMutablePointer<GOutputStream>(OpaquePointer(sourcePtr)), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(UInt(numBytesWritten))
            }, userData)

            g_bytes_unref(bytes)
        }
    }

    @MainActor
    public func writeAll(_ data: Data) async throws {
        try await fridaAsync(Void.self) { op in
            let buffer = data.withUnsafeBytes { ptr in g_memdup2(ptr.baseAddress, gsize(ptr.count)) }
            op.payload = buffer
            let userData = op.userData

            g_output_stream_write_all_async(self.output, buffer, gsize(data.count), self.ioPriority, op.cancellable, { sourcePtr, asyncResultPtr, userDataPtr in
                let op = InternalOp<Void>.takeRetained(from: userDataPtr!)

                let buffer = op.payload!
                op.payload = nil
                defer { g_free(buffer) }

                var bytesWritten: gsize = 0
                var rawError: UnsafeMutablePointer<GError>? = nil
                g_output_stream_write_all_finish(UnsafeMutablePointer<GOutputStream>(OpaquePointer(sourcePtr)), asyncResultPtr, &bytesWritten, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, userData)
        }
    }
}
