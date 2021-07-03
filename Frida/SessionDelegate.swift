import Foundation

@objc(FridaSessionDelegate)
public protocol SessionDelegate {
    func session(_ session: Session, didDetach reason: SessionDetachReason, crash: CrashDetails?)
}
