import Foundation
import Frida_Private

@objc(FridaPortalMembership)
public class PortalMembership: NSObject, NSCopying {
    private let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle

        super.init()
    }

    public func copy(with zone: NSZone?) -> Any {
        g_object_ref(gpointer(handle))
        return PortalMembership(handle: handle)
    }

    deinit {
        let h = gpointer(handle)
        Runtime.scheduleOnFridaThread {
            g_object_unref(h)
        }
    }

    public override var description: String {
        return "Frida.PortalMembership()"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        if let membership = object as? PortalMembership {
            return membership.handle == handle
        } else {
            return false
        }
    }

    public override var hash: Int {
        return handle.hashValue
    }

    @MainActor
    public func terminate() async throws {
        return try await fridaAsync(Void.self) { op in
            frida_portal_membership_terminate(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_portal_membership_terminate_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }
}
