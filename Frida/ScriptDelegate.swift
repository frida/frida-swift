public protocol ScriptDelegate: AnyObject {
    func scriptDestroyed(_ script: Script)
    func script(_ script: Script, didReceiveMessage message: Any, withData data: [UInt8]?)
}

public extension ScriptDelegate {
    func scriptDestroyed(_ script: Script) {}
    func script(_ script: Script, didReceiveMessage message: Any, withData data: [UInt8]?) {}
}
