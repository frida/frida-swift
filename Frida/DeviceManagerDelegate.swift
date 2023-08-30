import Foundation

@objc(FridaDeviceManagerDelegate)
public protocol DeviceManagerDelegate {
    @objc optional func deviceManager(_ manager: DeviceManager, didAddDevice device: Device)
    @objc optional func deviceManager(_ manager: DeviceManager, didRemoveDevice device: Device)
    @objc optional func deviceManagerDidChangeDevices(_ manager: DeviceManager)
}
