import Foundation

@objc(FridaScriptDelegate)
public protocol ScriptDelegate {
    @objc optional func scriptDestroyed(_ script: Script)
    @objc optional func script(_ script: Script, didReceiveMessage message: Any, withData data: Data?)
}
