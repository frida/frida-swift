import Foundation

@objc(FridaBusDelegate)
public protocol BusDelegate {
    @objc optional func busDetached(_ bus: Bus)
    @objc optional func bus(_ bus: Bus, didReceiveMessage message: Any, withData data: Data?)
}
