import Foundation
import Frida_Private

@objc(FridaDeviceManager)
public class DeviceManager: NSObject, NSCopying {
    public weak var delegate: DeviceManagerDelegate?

    private typealias AddedHandler = @convention(c) (_ manager: OpaquePointer, _ device: OpaquePointer, _ userData: gpointer) -> Void
    private typealias RemovedHandler = @convention(c) (_ manager: OpaquePointer, _ device: OpaquePointer, _ userData: gpointer) -> Void
    private typealias ChangedHandler = @convention(c) (_ manager: OpaquePointer, _ userData: gpointer) -> Void

    private let handle: OpaquePointer
    private var onChangedHandler: gulong = 0
    private var onAddedHandler: gulong = 0
    private var onRemovedHandler: gulong = 0

    public convenience override init() {
        frida_init()

        self.init(handle: frida_device_manager_new())
    }

    init(handle: OpaquePointer) {
        self.handle = handle

        super.init()

        let rawHandle = gpointer(handle)
        onAddedHandler = g_signal_connect_data(rawHandle, "added", unsafeBitCast(onAdded, to: GCallback.self),
                                               gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                               releaseConnection, GConnectFlags(0))
        onRemovedHandler = g_signal_connect_data(rawHandle, "removed", unsafeBitCast(onRemoved, to: GCallback.self),
                                                 gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                 releaseConnection, GConnectFlags(0))
        onChangedHandler = g_signal_connect_data(rawHandle, "changed", unsafeBitCast(onChanged, to: GCallback.self),
                                                 gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                 releaseConnection, GConnectFlags(0))
    }

    public func copy(with zone: NSZone?) -> Any {
        g_object_ref(gpointer(handle))
        return DeviceManager(handle: handle)
    }

    deinit {
        let rawHandle = gpointer(handle)
        let handlers = [onAddedHandler, onRemovedHandler, onChangedHandler]
        Runtime.scheduleOnFridaThread {
            for handler in handlers {
                g_signal_handler_disconnect(rawHandle, handler)
            }
            g_object_unref(rawHandle)
        }
    }

    public override var description: String {
        return "Frida.DeviceManager()"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        if let manager = object as? DeviceManager {
            return manager.handle == handle
        } else {
            return false
        }
    }

    public override var hash: Int {
        return handle.hashValue
    }

    @MainActor
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
            }, op.userData)
        }
    }

    @MainActor
    public var devices: [Device] {
        get async throws {
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
                        g_object_unref(gpointer(rawDevices))

                        op.resumeSuccess(resultDevices)
                    },
                    op.userData
                )
            }
        }
    }

    @MainActor
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

        return try await fridaAsync(Device.self) { op in
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
    }

    @MainActor
    public func removeRemoteDevice(address: String) async throws {
        return try await fridaAsync(Void.self) { op in
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

    private let onAdded: AddedHandler = { _, rawDevice, userData in
        let connection = Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawDevice))
        let device = Device(handle: rawDevice)

        if let manager = connection.instance {
            Runtime.scheduleOnMainThread {
                manager.delegate?.deviceManager?(manager, didAddDevice: device)
            }
        }
    }

    private let onRemoved: RemovedHandler = { _, rawDevice, userData in
        let connection = Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawDevice))
        let device = Device(handle: rawDevice)

        if let manager = connection.instance {
            Runtime.scheduleOnMainThread {
                manager.delegate?.deviceManager?(manager, didRemoveDevice: device)
            }
        }
    }

    private let onChanged: ChangedHandler = { _, userData in
        let connection = Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(userData).takeUnretainedValue()

        if let manager = connection.instance {
            Runtime.scheduleOnMainThread {
                manager.delegate?.deviceManagerDidChangeDevices?(manager)
            }
        }
    }

    private let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(data!).release()
    }
}
