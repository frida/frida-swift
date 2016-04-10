@objc(FridaDeviceDelegate)
public protocol DeviceDelegate {
    optional func deviceLost(device: Device)
    optional func device(device: Device, didSpawn spawn: SpawnDetails)
    optional func device(device: Device, didOutput data: NSData, toFileDescriptor fd: Int, fromProcess pid: UInt)
}
