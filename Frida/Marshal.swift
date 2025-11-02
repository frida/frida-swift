import AppKit
import Frida_Private

class Marshal {
    private static let gvariantStringType = g_variant_type_new("s")
    private static let gvariantInt64Type = g_variant_type_new("x")
    private static let gvariantBooleanType = g_variant_type_new("b")
    private static let gvariantVariantType = g_variant_type_new("v")
    private static let gvariantByteArrayType = g_variant_type_new("ay")
    private static let gvariantVarDictType = g_variant_type_new("a{sv}")
    private static let gvariantArrayType = g_variant_type_new("a*")

    private static let dateFormatter = makeDateFormatter()

    static func takeNativeError(_ error: UnsafeMutablePointer<GError>) -> Swift.Error {
        let domain = error.pointee.domain
        let code = error.pointee.code
        let message = String(cString: error.pointee.message)

        g_error_free(error)

        if domain == g_io_error_quark() &&
           code == Int32(G_IO_ERROR_CANCELLED.rawValue) {
            return CancellationError()
        }

        if domain == frida_error_quark() {
            let fridaCode = FridaError(UInt32(code))

            switch fridaCode {
            case FRIDA_ERROR_SERVER_NOT_RUNNING:
                return Error.serverNotRunning(message)
            case FRIDA_ERROR_EXECUTABLE_NOT_FOUND:
                return Error.executableNotFound(message)
            case FRIDA_ERROR_EXECUTABLE_NOT_SUPPORTED:
                return Error.executableNotSupported(message)
            case FRIDA_ERROR_PROCESS_NOT_FOUND:
                return Error.processNotFound(message)
            case FRIDA_ERROR_PROCESS_NOT_RESPONDING:
                return Error.processNotResponding(message)
            case FRIDA_ERROR_INVALID_ARGUMENT:
                return Error.invalidArgument(message)
            case FRIDA_ERROR_INVALID_OPERATION:
                return Error.invalidOperation(message)
            case FRIDA_ERROR_PERMISSION_DENIED:
                return Error.permissionDenied(message)
            case FRIDA_ERROR_ADDRESS_IN_USE:
                return Error.addressInUse(message)
            case FRIDA_ERROR_TIMED_OUT:
                return Error.timedOut(message)
            case FRIDA_ERROR_NOT_SUPPORTED:
                return Error.notSupported(message)
            case FRIDA_ERROR_PROTOCOL:
                return Error.protocolViolation(message)
            case FRIDA_ERROR_TRANSPORT:
                return Error.transport(message)
            default:
                fatalError("Unexpected Frida error code \(code)")
            }
        }

        fatalError("Unexpected GError domain \(domain) code \(code): \(message)")
    }

    static func dictionaryFromParametersDict(_ hashTable: OpaquePointer) -> [String: Any] {
        var result: [String: Any] = [:]

        var iter = GHashTableIter()
        g_hash_table_iter_init(&iter, hashTable)

        var rawKey: gpointer?
        var rawValue: gpointer?
        while g_hash_table_iter_next(&iter, &rawKey, &rawValue) != 0 {
            let key = String(cString: UnsafeRawPointer(rawKey!).assumingMemoryBound(to: Int8.self))
            let value = valueFromVariant(OpaquePointer(rawValue!))
            result[key] = value
        }

        return result
    }

    static func valueFromVariant(_ v: OpaquePointer) -> Any {
        if g_variant_is_of_type(v, gvariantStringType) != 0 {
            return stringFromVariant(v)
        }

        if g_variant_is_of_type(v, gvariantInt64Type) != 0 {
            return Int64(g_variant_get_int64(v))
        }

        if g_variant_is_of_type(v, gvariantBooleanType) != 0 {
            return g_variant_get_boolean(v) != 0
        }

        if g_variant_is_of_type(v, gvariantVariantType) != 0 {
            return valueFromVariant(g_variant_get_variant(v))
        }

        if g_variant_is_of_type(v, gvariantByteArrayType) != 0 {
            var count: gsize = 0
            return Data(bytes: g_variant_get_fixed_array(v, &count, 1), count: Int(count))
        }

        if g_variant_is_of_type(v, gvariantVarDictType) != 0 {
            var result: [String: Any] = [:]

            var iter = GVariantIter()
            g_variant_iter_init(&iter, v)

            while let entry = g_variant_iter_next_value(&iter) {
                let rawKey = g_variant_get_child_value(entry, 0)!;
                let rawValue = g_variant_get_child_value(entry, 1)!;

                let key = stringFromVariant(rawKey)
                let value = valueFromVariant(rawValue)
                result[key] = value

                g_variant_unref(rawValue)
                g_variant_unref(rawKey)
                g_variant_unref(entry)
            }

            return result
        }

        if g_variant_is_of_type(v, gvariantArrayType) != 0 {
            var result: [Any] = []

            var iter = GVariantIter()
            g_variant_iter_init(&iter, v)

            while let child = g_variant_iter_next_value(&iter) {
                result.append(valueFromVariant(child))
                g_variant_unref(child)
            }

            return result
        }

        return NSNull()
    }

    private static func stringFromVariant(_ v: OpaquePointer) -> String {
        return String(cString: UnsafeRawPointer(g_variant_get_string(v, nil)!).assumingMemoryBound(to: Int8.self))
    }

    static func dateFromISO8601(_ text: String) -> Date? {
        return dateFormatter.date(from: text)
    }

    private static func makeDateFormatter() -> ISO8601DateFormatter {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }

    static func iconFromVarDict(_ dict: [String: Any]) -> Icon {
        let formatString = dict["format"] as! String
        let rawData = dict["image"] as! Data
        let bytes = [UInt8](rawData)

        switch formatString {
        case "rgba":
            let w = dict["width"] as! Int64
            let h = dict["height"] as! Int64

            return .rgba(
                width: Int(w),
                height: Int(h),
                pixels: bytes
            )

        case "png":
            return .png(
                data: bytes
            )

        default:
            fatalError("Unexpected icon format from Frida: \(formatString)")
        }
    }

    static func arrayFromStrv(_ strv: UnsafeMutablePointer<UnsafeMutablePointer<gchar>?>) -> [String] {
        var result: [String] = []

        var cursor = strv
        while let str = cursor.pointee {
            result.append(String(cString: str))
            cursor += 1
        }

        return result
    }

    static func strvFromArray(_ array: [String]?) -> (UnsafeMutablePointer<UnsafeMutablePointer<gchar>?>?, gint) {
        var strv: UnsafeMutablePointer<UnsafeMutablePointer<gchar>?>?
        var length: gint

        if let array = array {
            strv = unsafeBitCast(g_malloc0(gsize((array.count + 1) * MemoryLayout<gpointer>.size)), to: UnsafeMutablePointer<UnsafeMutablePointer<gchar>?>.self)
            for (index, element) in array.enumerated() {
                strv!.advanced(by: index).pointee = g_strdup(element)
            }
            length = gint(array.count)
        } else {
            strv = nil
            length = -1
        }

        return (strv, length)
    }

    static func dictionaryFromEnvp(_ envp: UnsafeMutablePointer<UnsafeMutablePointer<gchar>?>) -> [String: String] {
        var result: [String: String] = [:]
        for pair in arrayFromStrv(envp) {
            let tokens = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let key: String = String(tokens[0])
            let value: String = String(tokens[1])
            result[key] = value
        }
        return result
    }

    static func envpFromDictionary(_ dict: [String: String]?) -> (UnsafeMutablePointer<UnsafeMutablePointer<gchar>?>?, gint) {
        var envp: UnsafeMutablePointer<UnsafeMutablePointer<gchar>?>?
        var length: gint

        if let dict = dict {
            envp = unsafeBitCast(g_malloc0(gsize((dict.count + 1) * MemoryLayout<gpointer>.size)), to: UnsafeMutablePointer<UnsafeMutablePointer<gchar>?>.self)
            for item in dict.enumerated() {
                envp!.advanced(by: item.offset).pointee = g_strdup(item.element.key + "=" + item.element.value)
            }
            length = gint(dict.count)
        } else {
            envp = nil
            length = -1
        }

        return (envp, length)
    }

    static func dataFromBytes(_ bytes: OpaquePointer) -> Data {
        var size: gsize = 0
        if let rawBytes = g_bytes_get_data(bytes, &size), size > 0 {
            g_bytes_ref(bytes)
            return Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: rawBytes), count: Int(size), deallocator: .custom({ (ptr, size) in
                g_bytes_unref(bytes)
            }))
        }
        return Data()
    }

    static func dataFromBytes(_ bytes: OpaquePointer!) -> Data? {
        if let bytes = bytes {
            return dataFromBytes(bytes)
        }
        return nil
    }

    static func bytesFromData(_ data: Data) -> OpaquePointer {
        return data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            return g_bytes_new(ptr.baseAddress, UInt(ptr.count))
        }
    }

    static func bytesFromData(_ data: Data?) -> OpaquePointer! {
        if let data = data {
            return bytesFromData(data)
        }
        return nil
    }

    static func certificateFromString(_ string: String) throws -> UnsafeMutablePointer<GTlsCertificate> {
        var result: UnsafeMutablePointer<GTlsCertificate>?
        var rawError: UnsafeMutablePointer<GError>? = nil
        if string.contains("\n") {
            result = g_tls_certificate_new_from_pem(string, -1, &rawError)
        } else {
            result = g_tls_certificate_new_from_file(string, &rawError)
        }
        if let rawError = rawError {
            let message = String(cString: rawError.pointee.message)
            g_error_free(rawError)
            throw Error.invalidArgument(message)
        }
        return result!
    }
}
