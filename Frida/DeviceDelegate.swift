public protocol DeviceDelegate {
    func deviceLost(device: Device)
    func device(device: Device, didSpawn spawn: SpawnDetails)
    func device(device: Device, didOutput data: NSData, toFileDescriptor fd: Int, fromProcess pid: UInt)
}
