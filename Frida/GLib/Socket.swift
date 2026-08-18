internal import FridaCore

#if !os(Windows)

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

extension GLib {
    public final class Socket: @unchecked Sendable {
        let handle: UnsafeMutablePointer<GSocket>

        init(handle: UnsafeMutablePointer<GSocket>) {
            self.handle = handle
        }

        deinit {
            g_object_unref(gpointer(handle))
        }

        public convenience init(adopting fileDescriptor: Int32) throws {
            var rawError: UnsafeMutablePointer<GError>? = nil
            let handle = g_socket_new_from_fd(fileDescriptor, &rawError)
            if let rawError {
                throw Marshal.takeNativeError(rawError)
            }
            self.init(handle: handle!)
        }

        public static func connect(unixPath: String) throws -> Socket {
            let address = g_unix_socket_address_new(unixPath)!
            defer { g_object_unref(gpointer(address)) }

            var rawError: UnsafeMutablePointer<GError>? = nil
            let handle = g_socket_new(G_SOCKET_FAMILY_UNIX, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_DEFAULT, &rawError)
            if let rawError {
                throw Marshal.takeNativeError(rawError)
            }

            let socket = Socket(handle: handle!)
            g_socket_connect(handle, UnsafeMutableRawPointer(address).assumingMemoryBound(to: GSocketAddress.self), nil, &rawError)
            if let rawError {
                throw Marshal.takeNativeError(rawError)
            }
            return socket
        }

        public static func pair() throws -> (Socket, Socket) {
            var descriptors: [Int32] = [-1, -1]
            guard socketpair(AF_UNIX, streamSocketTypeValue, 0, &descriptors) == 0 else {
                throw Frida.Error.transport("Unable to make a socket pair: \(String(cString: strerror(errno)))")
            }
            return (try Socket(adopting: descriptors[0]), try Socket(adopting: descriptors[1]))
        }

        #if canImport(Darwin)
        private static let streamSocketTypeValue = SOCK_STREAM
        #else
        private static let streamSocketTypeValue = Int32(SOCK_STREAM.rawValue)
        #endif

        public var fileDescriptor: Int32 {
            g_socket_get_fd(handle)
        }

        public func send(_ bytes: [UInt8], fileDescriptors: [Int32] = []) throws {
            var payload = bytes
            try payload.withUnsafeMutableBufferPointer { payload in
                var vector = GOutputVector(buffer: payload.baseAddress, size: gsize(payload.count))

                var messages: [UnsafeMutablePointer<GSocketControlMessage>?] = []
                if let rights = Self.rightsMessage(adopting: fileDescriptors) {
                    messages.append(rights)
                }
                defer { messages.forEach { g_object_unref(gpointer($0)) } }
                defer { messages.forEach { g_object_unref(gpointer($0)) } }

                var rawError: UnsafeMutablePointer<GError>? = nil
                withUnsafeMutablePointer(to: &vector) { vector in
                    messages.withUnsafeMutableBufferPointer { messages in
                        g_socket_send_message(handle, nil, vector, 1, messages.baseAddress, gint(messages.count), 0, nil, &rawError)
                    }
                }
                if let rawError {
                    throw Marshal.takeNativeError(rawError)
                }
            }
        }

        private static func rightsMessage(adopting fileDescriptors: [Int32]) -> UnsafeMutablePointer<GSocketControlMessage>? {
            guard !fileDescriptors.isEmpty else { return nil }

            var adoptable = fileDescriptors.map { dup($0) }
            return adoptable.withUnsafeMutableBytes { payload in
                g_socket_control_message_deserialize(
                    SOL_SOCKET, SCM_RIGHTS, gsize(payload.count), payload.baseAddress)
            }
        }

        public func receive(upTo count: Int) throws -> [UInt8] {
            var buffer = [UInt8](repeating: 0, count: count)
            var rawError: UnsafeMutablePointer<GError>? = nil
            let received = buffer.withUnsafeMutableBytes { buffer in
                g_socket_receive(handle, buffer.baseAddress, gsize(buffer.count), nil, &rawError)
            }
            if let rawError {
                throw Marshal.takeNativeError(rawError)
            }
            return Array(buffer[0..<max(Int(received), 0)])
        }

        public func close() {
            g_socket_close(handle, nil)
        }
    }
}

#endif
