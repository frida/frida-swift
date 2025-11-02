import Frida_Private

public final class Bus: Hashable {
    public weak var delegate: (any BusDelegate)?

    private typealias DetachHandler =
        @convention(c) (_ bus: OpaquePointer, _ userData: gpointer) -> Void
    private typealias MessageHandler =
        @convention(c) (_ bus: OpaquePointer,
                        _ json: UnsafePointer<gchar>,
                        _ data: OpaquePointer?,
                        _ userData: gpointer) -> Void

    private let handle: OpaquePointer
    private var onDetachedHandler: gulong = 0
    private var onMessageHandler: gulong = 0

    init(handle: OpaquePointer) {
        self.handle = handle

        let rawHandle = gpointer(handle)

        onDetachedHandler = g_signal_connect_data(
            rawHandle,
            "detached",
            unsafeBitCast(Bus.onDetached, to: GCallback.self),
            gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
            Bus.releaseConnection,
            GConnectFlags(0)
        )

        onMessageHandler = g_signal_connect_data(
            rawHandle,
            "message",
            unsafeBitCast(Bus.onMessage, to: GCallback.self),
            gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
            Bus.releaseConnection,
            GConnectFlags(0)
        )
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var isClosed: Bool {
        return frida_bus_is_detached(handle) != 0
    }

    public var description: String {
        return "Frida.Bus()"
    }

    public static func == (lhs: Bus, rhs: Bus) -> Bool {
        return lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }

    @MainActor
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

    private static let onDetached: DetachHandler = { _, userData in
        let connection = Unmanaged<SignalConnection<Bus>>.fromOpaque(userData).takeUnretainedValue()

        if let bus = connection.instance {
            Runtime.scheduleOnMainThread {
                bus.delegate?.busDetached(bus)
            }
        }
    }

    private static let onMessage: MessageHandler = { _, rawJson, rawBytes, userData in
        let connection = Unmanaged<SignalConnection<Bus>>.fromOpaque(userData).takeUnretainedValue()

        let message = Marshal.valueFromJSON(Marshal.stringFromCString(rawJson))
        let data: [UInt8]? = Marshal.arrayFromBytes(rawBytes)

        if let bus = connection.instance {
            Runtime.scheduleOnMainThread {
                bus.delegate?.bus(bus,
                                  didReceiveMessage: message,
                                  withData: data)
            }
        }
    }

    private static let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<Bus>>
            .fromOpaque(data!).release()
    }
}
