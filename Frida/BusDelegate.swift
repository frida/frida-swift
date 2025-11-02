public protocol BusDelegate: AnyObject {
    func busDetached(_ bus: Bus)
    func bus(_ bus: Bus, didReceiveMessage message: Any, withData data: [UInt8]?)
}

public extension BusDelegate {
    func busDetached(_ bus: Bus) {}
    func bus(_ bus: Bus, didReceiveMessage message: Any, withData data: [UInt8]?) {}
}
