@objc(FridaScriptDelegate)
public protocol ScriptDelegate {
    optional func scriptDestroyed(script: Script)
    optional func script(script: Script, didReceiveMessage message: AnyObject, withData data: NSData)
}
