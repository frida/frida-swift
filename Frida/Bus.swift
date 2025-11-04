import Frida_Private

public final class Bus: @unchecked Sendable, Hashable {
    public var events: Events {
        if isDetached {
            return Events { continuation in
                continuation.yield(.detached)
                continuation.finish()
            }
        } else {
            return eventSource.makeStream()
        }
    }

    public typealias Events = AsyncStream<Event>

    @frozen
    public enum Event {
        case detached
        case message(message: Any, data: [UInt8]?)
    }

    private let handle: OpaquePointer
    private let eventSource = AsyncEventSource<Event>()

    init(handle: OpaquePointer) {
        self.handle = handle

        connectSignal(instance: self, handle: handle, signal: "detached", handler: onDetached)
        connectSignal(instance: self, handle: handle, signal: "message", handler: onMessage)
    }

    deinit {
        eventSource.finish()
        g_object_unref(gpointer(handle))
    }

    public var isDetached: Bool {
        frida_bus_is_detached(handle) != 0
    }

    public var description: String {
        "Frida.Bus()"
    }

    public static func == (lhs: Bus, rhs: Bus) -> Bool {
        lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }

    public func attach() async throws {
        return try await fridaAsync(Void.self) { op in
            frida_bus_attach(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                    let op = InternalOp<Void>.takeRetained(from: userData!)

                    var rawError: UnsafeMutablePointer<GError>? = nil
                    frida_bus_attach_finish(
                        OpaquePointer(sourcePtr),
                        asyncResultPtr,
                        &rawError
                    )

                    if let rawError {
                        op.resumeFailure(Marshal.takeNativeError(rawError))
                        return
                    }

                    op.resumeSuccess(())
                },
                op.userData
            )
        }
    }

    public func post(_ message: Any, data: [UInt8]? = nil) {
        let json = Marshal.jsonFromValue(message)
        let rawData = Marshal.bytesFromArray(data)
        frida_bus_post(handle, json, rawData)
        g_bytes_unref(rawData)
    }

    private let onDetached: @convention(c) (OpaquePointer, gpointer) -> Void = { _, userData in
        let connection = Unmanaged<SignalConnection<Bus>>.fromOpaque(userData).takeUnretainedValue()

        if let bus = connection.instance {
            bus.publish(.detached)
            bus.eventSource.finish()
        }
    }

    private let onMessage: @convention(c) (OpaquePointer, UnsafePointer<gchar>, OpaquePointer?, gpointer) -> Void = { _, rawJson, rawBytes, userData in
        let connection = Unmanaged<SignalConnection<Bus>>.fromOpaque(userData).takeUnretainedValue()

        let message = Marshal.valueFromJSON(Marshal.stringFromCString(rawJson))
        let data: [UInt8]? = Marshal.arrayFromBytes(rawBytes)

        connection.instance?.publish(.message(message: message, data: data))
    }

    private func publish(_ event: Event) {
        eventSource.yield(event)
    }
}
