@objc(FridaDeviceDelegate)
public protocol DeviceDelegate {
    @objc optional func deviceLost(_ device: Device)
    @objc optional func device(_ device: Device, didAddSpawn spawn: SpawnDetails)
    @objc optional func device(_ device: Device, didRemoveSpawn spawn: SpawnDetails)
    @objc optional func device(_ device: Device, didOutput data: Data, toFileDescriptor fd: Int, fromProcess pid: UInt)
}
