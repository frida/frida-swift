    private let store = DeviceStore()

    public typealias DeviceSnapshots = AsyncStream<[Device]>
    public typealias DeviceChanges = AsyncStream<DeviceChange>

    public enum DeviceChange: Sendable {
        case appeared(Device)
        case disappeared(Device)
    }

    public convenience init() {
        Runtime.ensureInitialized()
        self.init(handle: frida_device_manager_new())
    }

    public func currentDevices() async -> [Device] {
        await store.snapshot()
    }

    public func snapshots() async -> DeviceSnapshots {
        await store.stream()
    }

    public func changes() async -> DeviceChanges {
        await store.changeStream()
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

        let deviceHandle = try await fridaAsync(OpaquePointer.self) { op in
            frida_device_manager_add_remote_device(self.handle, address, options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<OpaquePointer>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawDeviceHandle = frida_device_manager_add_remote_device_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(rawDeviceHandle!)
            }, op.userData)

            g_object_unref(gpointer(options))
        }

        return await store.deviceForHandle(deviceHandle)
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
                    resultDevices.append(Device(handle: frida_device_list_get(rawDevices, i)!))
                }

                op.resumeSuccess(resultDevices)
                g_object_unref(gpointer(rawDevices))
            }, op.userData)
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
