import FridaCore

public final class DeviceManager: @unchecked Sendable {
    private let handle: OpaquePointer
    private let store = DeviceStore()

    public typealias DeviceSnapshots = AsyncStream<[Device]>

    public init() {
        Runtime.ensureInitialized()

        handle = frida_device_manager_new()

        connectSignal(instance: self, handle: handle, signal: "added", handler: onAdded)
        connectSignal(instance: self, handle: handle, signal: "removed", handler: onRemoved)

        Task {
            await self.performInitialDiscovery()
        }
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public func currentDevices() async -> [Device] {
        await store.snapshot()
    }

    public func snapshots() async -> DeviceSnapshots {
        await store.stream()
    }

    public func close() async throws {
        try await fridaAsync(Void.self) { op in
            frida_device_manager_close(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                    let op = InternalOp<Void>.takeRetained(from: userData!)

                    var rawError: UnsafeMutablePointer<GError>? = nil
                    frida_device_manager_close_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

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

    @discardableResult
    public func addRemoteDevice(
        address: String,
        certificate: String? = nil,
        origin: String? = nil,
        token: String? = nil,
        keepaliveInterval: Int? = nil
    ) async throws -> Device {
        let options = frida_remote_device_options_new()
        defer { g_object_unref(gpointer(options)) }

        if let certificate {
            let rawCertificate = try Marshal.certificateFromString(certificate)
            frida_remote_device_options_set_certificate(options, rawCertificate)
            g_object_unref(rawCertificate)
        }

        if let origin {
            frida_remote_device_options_set_origin(options, origin)
        }

        if let token {
            frida_remote_device_options_set_token(options, token)
        }

        if let keepaliveInterval {
            frida_remote_device_options_set_keepalive_interval(options, gint(keepaliveInterval))
        }

        g_object_ref(gpointer(options))

        let handle = try await fridaAsync(OpaquePointer.self) { op in
            frida_device_manager_add_remote_device(self.handle, address, options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                    let op = InternalOp<OpaquePointer>.takeRetained(from: userData!)

                    var rawError: UnsafeMutablePointer<GError>? = nil
                    let rawDeviceHandle = frida_device_manager_add_remote_device_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                    if let rawError {
                        op.resumeFailure(Marshal.takeNativeError(rawError))
                        return
                    }

                    op.resumeSuccess(rawDeviceHandle!)
                },
                op.userData
            )

            g_object_unref(gpointer(options))
        }

        return await store.deviceForHandle(handle)
    }

    public func removeRemoteDevice(address: String) async throws {
        try await fridaAsync(Void.self) { op in
            frida_device_manager_remove_remote_device(self.handle, address, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                    let op = InternalOp<Void>.takeRetained(from: userData!)

                    var rawError: UnsafeMutablePointer<GError>? = nil
                    frida_device_manager_remove_remote_device_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

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

    private func performInitialDiscovery() async {
        do {
            let snapshot = try await fetchInitialDevices()
            await store.handleInitialSnapshot(snapshot)
        } catch {
            await store.handleInitialSnapshot([])
        }
    }

    private func fetchInitialDevices() async throws -> [Device] {
        try await fridaAsync([Device].self) { op in
            frida_device_manager_enumerate_devices(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                    let op = InternalOp<[Device]>.takeRetained(from: userData!)

                    var rawError: UnsafeMutablePointer<GError>? = nil
                    let rawDevices = frida_device_manager_enumerate_devices_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                    if let rawError {
                        op.resumeFailure(Marshal.takeNativeError(rawError))
                        return
                    }

                    var resultDevices: [Device] = []
                    let count = frida_device_list_size(rawDevices)
                    for i in 0 ..< count {
                        let devHandle = frida_device_list_get(rawDevices, i)!
                        resultDevices.append(Device(handle: devHandle))
                    }

                    op.resumeSuccess(resultDevices)

                    g_object_unref(gpointer(rawDevices))
                },
                op.userData
            )
        }
    }

    private let onAdded: @convention(c) (OpaquePointer, OpaquePointer, gpointer) -> Void = { _, rawDevice, userData in
        let connection = Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(userData).takeUnretainedValue()

        Task {
            _ = await connection.instance?.store.deviceAppeared(with: rawDevice)
        }
    }

    private let onRemoved: @convention(c) (OpaquePointer, OpaquePointer, gpointer) -> Void = { _, rawDevice, userData in
        let connection = Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(userData).takeUnretainedValue()

        Task {
            await connection.instance?.store.deviceDisappeared(with: rawDevice)
        }
    }
}

actor DeviceStore {
    private var devices: [Device] = []
    private let events = AsyncEventSource<[Device]>()

    private var waiters: [OpaquePointer: [CheckedContinuation<Device, Never>]] = [:]

    func handleInitialSnapshot(_ devices: [Device]) {
        self.devices = devices
        events.yield(self.devices)
    }

    func deviceAppeared(with handle: OpaquePointer) -> Device {
        if let existing = devices.first(where: { $0.handle == handle }) {
            if let continuations = waiters.removeValue(forKey: handle) {
                for c in continuations {
                    c.resume(returning: existing)
                }
            }
            return existing
        }

        g_object_ref(gpointer(handle))
        let device = Device(handle: handle)
        devices.append(device)
        events.yield(devices)

        if let continuations = waiters.removeValue(forKey: handle) {
            for c in continuations {
                c.resume(returning: device)
            }
        }

        return device
    }

    func deviceDisappeared(with handle: OpaquePointer) {
        devices.removeAll { $0.handle == handle }
        events.yield(devices)
    }

    func deviceForHandle(_ handle: OpaquePointer) async -> Device {
        if let existing = devices.first(where: { $0.handle == handle }) {
            return existing
        }

        return await withCheckedContinuation { continuation in
            waiters[handle, default: []].append(continuation)
        }
    }

    func snapshot() -> [Device] {
        devices
    }

    func stream() -> AsyncStream<[Device]> {
        events.makeStream()
    }

    func finish() {
        events.finish()
    }
}
