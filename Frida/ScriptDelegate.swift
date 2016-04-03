public protocol ScriptDelegate {
    func scriptDestroyed(script: Script)
    func script(script: Script, didReceiveMessage message: AnyObject, withData data: NSData)
}
