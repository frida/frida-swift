@objc(FridaDeviceManagerDelegate)
public protocol DeviceManagerDelegate {
    optional func deviceManagerDidChangeDevices(manager: DeviceManager)
    optional func deviceManager(manager: DeviceManager, didAddDevice device: Device)
    optional func deviceManager(manager: DeviceManager, didRemoveDevice device: Device)
}
