public protocol SessionDelegate: AnyObject {
    func session(_ session: Session, didDetach reason: SessionDetachReason, crash: CrashDetails?)
}
