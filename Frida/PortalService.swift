import Frida_Private

public final class PortalService: @unchecked Sendable, CustomStringConvertible, Equatable, Hashable {
    public var events: Events {
        eventSource.makeStream()
    }

    public typealias Events = AsyncStream<Event>

    @frozen
    public enum Event {
        case authenticated(connectionId: ConnectionID, sessionInfo: String)
        case controllerConnected(connectionId: ConnectionID, remoteAddress: SocketAddress)
        case controllerDisconnected(connectionId: ConnectionID, remoteAddress: SocketAddress)
        case message(connectionId: ConnectionID, message: Any, data: [UInt8]?)
        case nodeConnected(connectionId: ConnectionID, remoteAddress: SocketAddress)
        case nodeDisconnected(connectionId: ConnectionID, remoteAddress: SocketAddress)
        case nodeJoined(connectionId: ConnectionID, application: ApplicationDetails)
        case nodeLeft(connectionId: ConnectionID, application: ApplicationDetails)
        case subscribe(connectionId: ConnectionID)
    }

    public typealias ConnectionID = UInt32

    private let handle: OpaquePointer
    private let eventSource = AsyncEventSource<Event>()

    public init(clusterParameters: EndpointParameters, controlParameters: EndpointParameters? = nil) {
        handle = frida_portal_service_new(clusterParameters.handle, controlParameters?.handle)

        connectSignal(instance: self, handle: handle, signal: "authenticated", handler: onAuthenticated)
        connectSignal(instance: self, handle: handle, signal: "controller-connected", handler: onControllerConnected)
        connectSignal(instance: self, handle: handle, signal: "controller-disconnected", handler: onControllerDisconnected)
        connectSignal(instance: self, handle: handle, signal: "message", handler: onMessage)
        connectSignal(instance: self, handle: handle, signal: "node-connected", handler: onNodeConnected)
        connectSignal(instance: self, handle: handle, signal: "node-disconnected", handler: onNodeDisconnected)
        connectSignal(instance: self, handle: handle, signal: "node-joined", handler: onNodeJoined)
        connectSignal(instance: self, handle: handle, signal: "node-left", handler: onNodeLeft)
        connectSignal(instance: self, handle: handle, signal: "subscribe", handler: onSubscribe)
    }

    deinit {
        eventSource.finish()
        g_object_unref(gpointer(handle))
    }

    public var description: String {
        "Frida.PortalService()"
    }

    public static func == (lhs: PortalService, rhs: PortalService) -> Bool {
        lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }

    public var device: Device {
        let raw = frida_portal_service_get_device(handle)!
        g_object_ref(gpointer(raw))
        return Device(handle: raw)
    }

    public var clusterParameters: EndpointParameters {
        let raw = frida_portal_service_get_cluster_params(handle)!
        g_object_ref(gpointer(raw))
        return EndpointParameters.init(handle: raw)
    }

    public var controlParameters: EndpointParameters? {
        guard let raw = frida_portal_service_get_control_params(handle) else { return nil }
        g_object_ref(gpointer(raw))
        return EndpointParameters.init(handle: raw)
    }

    public func start() async throws {
        try await fridaAsync(Void.self) { op in
            frida_portal_service_start(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_portal_service_start_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func stop() async throws {
        try await fridaAsync(Void.self) { op in
            frida_portal_service_stop(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_portal_service_stop_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func kick(_ connectionId: ConnectionID) {
        frida_portal_service_kick(handle, connectionId)
    }

    public func post(
        to connectionId: ConnectionID,
        message: Any,
        data: [UInt8]? = nil
    ) {
        let json = Marshal.jsonFromValue(message)
        let rawData = Marshal.bytesFromArray(data)

        frida_portal_service_post(handle, connectionId, json, rawData)
        g_bytes_unref(rawData)
    }

    public func narrowcast(
        tag: String,
        message: Any,
        data: [UInt8]? = nil
    ) {
        let json = Marshal.jsonFromValue(message)
        let rawData = Marshal.bytesFromArray(data)

        frida_portal_service_narrowcast(handle, tag, json, rawData)

        g_bytes_unref(rawData)
    }

    public func broadcast(
        message: Any,
        data: [UInt8]? = nil
    ) {
        let json = Marshal.jsonFromValue(message)
        let rawData = Marshal.bytesFromArray(data)

        frida_portal_service_broadcast(handle, json, rawData)
        g_bytes_unref(rawData)
    }

    public func enumerateTags(for connectionId: ConnectionID) -> [String] {
        var length: gint = 0
        guard let rawVector = frida_portal_service_enumerate_tags(handle, connectionId, &length) else {
            return []
        }

        var tags: [String] = []
        tags.reserveCapacity(Int(length))

        for idx in 0..<Int(length) {
            guard let cstr = rawVector[idx] else { continue }
            tags.append(Marshal.stringFromCString(cstr))
        }

        g_strfreev(rawVector)
        return tags
    }

    public func tag(_ connectionId: ConnectionID, tag: String) {
        frida_portal_service_tag(handle, connectionId, tag)
    }

    public func untag(_ connectionId: ConnectionID, tag: String) {
        frida_portal_service_untag(handle, connectionId, tag)
    }

    private func publish(_ event: Event) {
        eventSource.yield(event)
    }

    public struct SocketAddress: CustomStringConvertible {
        internal let handle: OpaquePointer

        public var description: String {
            "SocketAddress(\(Unmanaged<AnyObject>.fromOpaque(UnsafeMutableRawPointer(handle)).toOpaque()))"
        }
    }

    private let onAuthenticated: @convention(c) (OpaquePointer, guint, UnsafePointer<gchar>, gpointer) -> Void = { _, rawConnectionId, rawSessionInfo, userData in
        let connection = Unmanaged<SignalConnection<PortalService>>.fromOpaque(userData).takeUnretainedValue()

        guard let service = connection.instance else { return }

        let sessionInfo = Marshal.stringFromCString(rawSessionInfo)
        service.publish(.authenticated(connectionId: ConnectionID(rawConnectionId),
                                       sessionInfo: sessionInfo))
    }

    private let onControllerConnected: @convention(c) (OpaquePointer, guint, OpaquePointer, gpointer) -> Void = { _, rawConnectionId, rawSocketAddress, userData in
        let connection = Unmanaged<SignalConnection<PortalService>>.fromOpaque(userData).takeUnretainedValue()

        guard let service = connection.instance else { return }

        let address = SocketAddress(handle: rawSocketAddress)
        service.publish(.controllerConnected(connectionId: ConnectionID(rawConnectionId),
                                             remoteAddress: address))
    }

    private let onControllerDisconnected: @convention(c) (OpaquePointer, guint, OpaquePointer, gpointer) -> Void = { _, rawConnectionId, rawSocketAddress, userData in
        let connection = Unmanaged<SignalConnection<PortalService>>.fromOpaque(userData).takeUnretainedValue()

        guard let service = connection.instance else { return }

        let address = SocketAddress(handle: rawSocketAddress)
        service.publish(.controllerDisconnected(connectionId: ConnectionID(rawConnectionId),
                                                remoteAddress: address))
    }

    private let onMessage: @convention(c) (OpaquePointer, guint, UnsafePointer<gchar>, OpaquePointer?, gpointer) -> Void = { _, rawConnectionId, rawJson, rawData, userData in
        let connection = Unmanaged<SignalConnection<PortalService>>.fromOpaque(userData).takeUnretainedValue()

        guard let service = connection.instance else { return }

        let jsonString = Marshal.stringFromCString(rawJson)
        guard let parsedAny = try? Marshal.valueFromJSON(jsonString) else { return }
        let dataBytes = Marshal.arrayFromBytes(rawData)

        service.publish(.message(connectionId: ConnectionID(rawConnectionId),
                                 message: parsedAny,
                                 data: dataBytes))
    }

    private let onNodeConnected: @convention(c) (OpaquePointer, guint, OpaquePointer, gpointer) -> Void = { _, rawConnectionId, rawSocketAddress, userData in
        let connection = Unmanaged<SignalConnection<PortalService>>.fromOpaque(userData).takeUnretainedValue()

        guard let service = connection.instance else { return }

        let address = SocketAddress(handle: rawSocketAddress)
        service.publish(.nodeConnected(connectionId: ConnectionID(rawConnectionId),
                                       remoteAddress: address))
    }

    private let onNodeDisconnected: @convention(c) (OpaquePointer, guint, OpaquePointer, gpointer) -> Void = { _, rawConnectionId, rawSocketAddress, userData in
        let connection = Unmanaged<SignalConnection<PortalService>>.fromOpaque(userData).takeUnretainedValue()

        guard let service = connection.instance else { return }

        let address = SocketAddress(handle: rawSocketAddress)
        service.publish(.nodeDisconnected(connectionId: ConnectionID(rawConnectionId),
                                          remoteAddress: address))
    }

    private let onNodeJoined: @convention(c) (OpaquePointer, guint, OpaquePointer, gpointer) -> Void = { _, rawConnectionId, rawApplication, userData in
        let connection = Unmanaged<SignalConnection<PortalService>>.fromOpaque(userData).takeUnretainedValue()

        guard let service = connection.instance else { return }

        let application = ApplicationDetails(handle: rawApplication)
        service.publish(.nodeJoined(connectionId: ConnectionID(rawConnectionId),
                                    application: application))
    }

    private let onNodeLeft: @convention(c) (OpaquePointer, guint, OpaquePointer, gpointer) -> Void = { _, rawConnectionId, rawApplication, userData in
        let connection = Unmanaged<SignalConnection<PortalService>>.fromOpaque(userData).takeUnretainedValue()

        guard let service = connection.instance else { return }

        let application = ApplicationDetails(handle: rawApplication)
        service.publish(.nodeLeft(connectionId: ConnectionID(rawConnectionId),
                                  application: application))
    }

    private let onSubscribe: @convention(c) (OpaquePointer, guint, gpointer) -> Void = { _, rawConnectionId, userData in
        let connection = Unmanaged<SignalConnection<PortalService>>.fromOpaque(userData).takeUnretainedValue()

        guard let service = connection.instance else { return }

        service.publish(.subscribe(connectionId: ConnectionID(rawConnectionId)))
    }
}
