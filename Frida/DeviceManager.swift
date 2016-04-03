import CFrida

public class DeviceManager {
    public var delegate: DeviceManagerDelegate?

    public typealias CloseComplete = () -> Void

    public typealias EnumerateDevicesComplete = (result: EnumerateDevicesResult) -> Void
    public typealias EnumerateDevicesResult = () throws -> [Device]

    public typealias AddRemoteDeviceComplete = (result: AddRemoteDeviceResult) -> Void
    public typealias AddRemoteDeviceResult = () throws -> Device

    public typealias RemoveRemoteDeviceComplete = (result: RemoveRemoteDeviceResult) -> Void
    public typealias RemoveRemoteDeviceResult = () throws -> Bool

    private typealias ChangedHandler = @convention(c) (manager: COpaquePointer, userData: gpointer) -> Void
    private typealias AddedHandler = @convention(c) (manager: COpaquePointer, device: COpaquePointer, userData: gpointer) -> Void
    private typealias RemovedHandler = @convention(c) (manager: COpaquePointer, device: COpaquePointer, userData: gpointer) -> Void

    private let handle: COpaquePointer
    private var onChangedHandler: gulong = 0
    private var onAddedHandler: gulong = 0
    private var onRemovedHandler: gulong = 0

    public init() {
        frida_init()

        handle = frida_device_manager_new()

        let rawHandle = gpointer(handle)
        onChangedHandler = g_signal_connect_data(rawHandle, "changed", unsafeBitCast(onChanged, GCallback.self),
                                                 gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                 releaseConnection, GConnectFlags(0))
        onAddedHandler = g_signal_connect_data(rawHandle, "added", unsafeBitCast(onAdded, GCallback.self),
                                               gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                               releaseConnection, GConnectFlags(0))
        onRemovedHandler = g_signal_connect_data(rawHandle, "removed", unsafeBitCast(onRemoved, GCallback.self),
                                                 gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                 releaseConnection, GConnectFlags(0))
    }

    deinit {
        let rawHandle = gpointer(handle)
        let handlers = [onChangedHandler, onAddedHandler, onRemovedHandler]
        Runtime.scheduleOnFridaThread() {
            for handler in handlers {
                g_signal_handler_disconnect(rawHandle, handler)
            }
            g_object_unref(rawHandle)
        }
    }

    public func close(completionHandler: CloseComplete = {}) {
        Runtime.scheduleOnFridaThread() {
            frida_device_manager_close(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<CloseComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                frida_device_manager_close_finish(COpaquePointer(source), result)

                Runtime.scheduleOnMainThread() {
                    operation.completionHandler()
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<CloseComplete>(completionHandler)).toOpaque()))
        }
    }

    public func enumerateDevices(completionHandler: EnumerateDevicesComplete) {
        Runtime.scheduleOnFridaThread() {
            frida_device_manager_enumerate_devices(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnumerateDevicesComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                let rawDevices = frida_device_manager_enumerate_devices_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread() {
                        operation.completionHandler() { throw error }
                    }
                    return
                }

                var devices = [Device]()
                let numberOfDevices = frida_device_list_size(rawDevices)
                for index in 0..<numberOfDevices {
                    let device = Device(handle: frida_device_list_get(rawDevices, index))
                    devices.append(device)
                }
                g_object_unref(gpointer(rawDevices))

                Runtime.scheduleOnMainThread() {
                    operation.completionHandler() { devices }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<EnumerateDevicesComplete>(completionHandler)).toOpaque()))
        }
    }

    public func addRemoteDevice(host: String, completionHandler: AddRemoteDeviceComplete = { _ in }) {
        Runtime.scheduleOnFridaThread() {
            frida_device_manager_add_remote_device(self.handle, host, { source, result, data in
                let operation = Unmanaged<AsyncOperation<AddRemoteDeviceComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                let rawDevice = frida_device_manager_add_remote_device_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread() {
                        operation.completionHandler() { throw error }
                    }
                    return
                }

                let device = Device(handle: rawDevice)

                Runtime.scheduleOnMainThread() {
                    operation.completionHandler() { device }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<AddRemoteDeviceComplete>(completionHandler)).toOpaque()))
        }
    }

    public func removeRemoteDevice(host: String, completionHandler: RemoveRemoteDeviceComplete = { _ in }) {
        Runtime.scheduleOnFridaThread() {
            frida_device_manager_remove_remote_device(self.handle, host, { source, result, data in
                let operation = Unmanaged<AsyncOperation<RemoveRemoteDeviceComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                frida_device_manager_remove_remote_device_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread() {
                        operation.completionHandler() { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread() {
                    operation.completionHandler() { true }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<RemoveRemoteDeviceComplete>(completionHandler)).toOpaque()))
        }
    }

    private let onChanged: ChangedHandler = { _, userData in
        let connection = Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(COpaquePointer(userData)).takeUnretainedValue()

        if let manager = connection.instance {
            Runtime.scheduleOnMainThread() {
                manager.delegate?.deviceManagerDidChangeDevices(manager)
            }
        }
    }

    private let onAdded: AddedHandler = { _, rawDevice, userData in
        let connection = Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(COpaquePointer(userData)).takeUnretainedValue()

        g_object_ref(gpointer(rawDevice))
        let device = Device(handle: rawDevice)

        if let manager = connection.instance {
            Runtime.scheduleOnMainThread() {
                manager.delegate?.deviceManager(manager, didAddDevice: device)
            }
        }
    }

    private let onRemoved: RemovedHandler = { _, rawDevice, userData in
        let connection = Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(COpaquePointer(userData)).takeUnretainedValue()

        g_object_ref(gpointer(rawDevice))
        let device = Device(handle: rawDevice)

        if let manager = connection.instance {
            Runtime.scheduleOnMainThread() {
                manager.delegate?.deviceManager(manager, didRemoveDevice: device)
            }
        }
    }

    private let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<DeviceManager>>.fromOpaque(COpaquePointer(data)).release()
    }
}
