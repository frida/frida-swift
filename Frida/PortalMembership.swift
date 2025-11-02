import Frida_Private

public final class PortalMembership: CustomStringConvertible, Equatable, Hashable {
    private let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var description: String {
        return "Frida.PortalMembership()"
    }

    public static func == (lhs: PortalMembership, rhs: PortalMembership) -> Bool {
        return lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
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
