import Combine
import Frida_Private

public final class DeviceManager: ObservableObject {
    @Published public private(set) var devices: [Device] = []
    @Published public private(set) var discoveryState: DiscoveryState = .discovering

    @frozen
    public enum DiscoveryState: Equatable {
        case discovering
        case ready
    }

    private let handle: OpaquePointer

    private typealias AddedHandler = @convention(c) (
        _ manager: OpaquePointer,
        _ device: OpaquePointer,
        _ userData: gpointer
    ) -> Void

    private typealias RemovedHandler = @convention(c) (
        _ manager: OpaquePointer,
        _ device: OpaquePointer,
        _ userData: gpointer
    ) -> Void

    public init() {
        frida_init()

        handle = frida_device_manager_new()

        setupSignals()

        Task {
            await self.performInitialDiscovery()
        }
    }

    deinit {
        g_object_unref(gpointer(handle))
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

        let newDevice = try await fridaAsync(Device.self) { op in
            frida_device_manager_add_remote_device(self.handle, address, options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                    let op = InternalOp<Device>.takeRetained(from: userData!)

                    var rawError: UnsafeMutablePointer<GError>? = nil
                    let rawDeviceHandle = frida_device_manager_add_remote_device_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                    if let rawError {
                        op.resumeFailure(Marshal.takeNativeError(rawError))
                        return
                    }

                    let device = Device(handle: rawDeviceHandle!)
                    op.resumeSuccess(device)
                },
                op.userData
            )

            g_object_unref(gpointer(options))
        }

        return newDevice
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
            self.devices = snapshot
        } catch {
            self.devices = []
        }
        self.discoveryState = .ready
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

    private func handleAdded(_ device: Device) {
        self.devices.append(device)
    }

    private func handleRemoved(_ device: Device) {
        self.devices.removeAll { $0 == device }
    }

    private func setupSignals() {
        let rawHandle = gpointer(handle)

        g_signal_connect_data(
            rawHandle,
            "added",
            unsafeBitCast(DeviceManager.onAdded, to: GCallback.self),
            gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
            DeviceManager.releaseConnection,
            GConnectFlags(0)
        )

        g_signal_connect_data(
            rawHandle,
            "removed",
            unsafeBitCast(DeviceManager.onRemoved, to: GCallback.self),
            gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
            DeviceManager.releaseConnection,
            GConnectFlags(0)
        )
    }

    private static let onAdded: AddedHandler = { _, rawDevice, userData in
        let connection = Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawDevice))
        let device = Device(handle: rawDevice)

        if let manager = connection.instance {
            Runtime.scheduleOnMainThread {
                manager.handleAdded(device)
            }
        }
    }

    private static let onRemoved: RemovedHandler = { _, rawDevice, userData in
        let connection = Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawDevice))
        let device = Device(handle: rawDevice)

        if let manager = connection.instance {
            Runtime.scheduleOnMainThread {
                manager.handleRemoved(device)
            }
        }
    }

    private static let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(data!).release()
    }
}
