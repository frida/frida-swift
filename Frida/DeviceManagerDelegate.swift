@objc(FridaDeviceManagerDelegate)
public protocol DeviceManagerDelegate {
    @objc optional func deviceManagerDidChangeDevices(_ manager: DeviceManager)
    @objc optional func deviceManager(_ manager: DeviceManager, didAddDevice device: Device)
    @objc optional func deviceManager(_ manager: DeviceManager, didRemoveDevice device: Device)
}
