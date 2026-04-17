import FridaCore

public protocol WebRequestHandler: AnyObject {
    var handle: OpaquePointer { get }
}

public final class WebRequest: @unchecked Sendable {
    internal let handle: OpaquePointer

    public let method: String
    public let path: String
    public let queryString: String?
    public let body: [UInt8]?

    internal init(handle: OpaquePointer) {
        self.handle = handle
        g_object_ref(gpointer(handle))

        self.method = String(cString: frida_web_request_get_method(handle))
        self.path = String(cString: frida_web_request_get_path(handle))
        if let raw = frida_web_request_get_query_string(handle) {
            self.queryString = String(cString: raw)
        } else {
            self.queryString = nil
        }
        self.body = Marshal.arrayFromBytes(frida_web_request_get_body(handle))
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public func forEachHeader(_ callback: (String, String) -> Void) {
        typealias Visitor = (String, String) -> Void
        withoutActuallyEscaping(callback) { escaping in
            var box = escaping
            withUnsafeMutablePointer(to: &box) { boxPtr in
                frida_web_request_foreach_header(handle, { namePtr, valuePtr, userData in
                    let cbPtr = userData!.assumingMemoryBound(to: Visitor.self)
                    cbPtr.pointee(String(cString: namePtr!), String(cString: valuePtr!))
                }, UnsafeMutableRawPointer(boxPtr))
            }
        }
    }
}

public final class WebResponse: @unchecked Sendable {
    public let handle: OpaquePointer

    public init(status: UInt32, body: [UInt8]) {
        Runtime.ensureInitialized()
        let rawBody = Marshal.bytesFromArray(body)
        self.handle = frida_web_response_new(status, rawBody)
        g_bytes_unref(rawBody)
    }

    internal init(handle: OpaquePointer) {
        self.handle = handle
        g_object_ref(gpointer(handle))
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public func addHeader(_ name: String, _ value: String) {
        frida_web_response_add_header(handle, name, value)
    }
}
