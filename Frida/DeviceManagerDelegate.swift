public protocol DeviceManagerDelegate {
    func deviceManagerDidChangeDevices(manager: DeviceManager)
    func deviceManager(manager: DeviceManager, didAddDevice device: Device)
    func deviceManager(manager: DeviceManager, didRemoveDevice device: Device)
}
