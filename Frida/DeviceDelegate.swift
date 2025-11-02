public protocol DeviceDelegate: AnyObject {
    func deviceLost(_ device: Device)
    func device(_ device: Device, didAddSpawn spawn: SpawnDetails)
    func device(_ device: Device, didRemoveSpawn spawn: SpawnDetails)
    func device(_ device: Device, didAddChild spawn: ChildDetails)
    func device(_ device: Device, didRemoveChild spawn: ChildDetails)
    func device(_ device: Device, didObserveCrash crash: CrashDetails)
    func device(_ device: Device, didOutput data: [UInt8], toFileDescriptor fd: Int, fromProcess pid: UInt)
    func device(_ device: Device, didUninject id: UInt)
}

public extension DeviceDelegate {
    func deviceLost(_ device: Device) {}
    func device(_ device: Device, didAddSpawn spawn: SpawnDetails) {}
    func device(_ device: Device, didRemoveSpawn spawn: SpawnDetails) {}
    func device(_ device: Device, didAddChild spawn: ChildDetails) {}
    func device(_ device: Device, didRemoveChild spawn: ChildDetails) {}
    func device(_ device: Device, didObserveCrash crash: CrashDetails) {}
    func device(_ device: Device, didOutput data: [UInt8], toFileDescriptor fd: Int, fromProcess pid: UInt) {}
    func device(_ device: Device, didUninject id: UInt) {}
}
