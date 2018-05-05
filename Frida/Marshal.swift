import CFrida

class Marshal {
    static func takeNativeError(_ error: UnsafeMutablePointer<GError>) -> Error {
        let code = FridaError.init(UInt32(error.pointee.code))
        let message = String(cString: error.pointee.message)

        g_error_free(error)

        switch code {
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
            fatalError("Unexpected Frida error code")
        }
    }

    static func imageFromIcon(_ icon: OpaquePointer?) -> NSImage? {
        if icon == nil {
            return nil
        }

        let width = Int(frida_icon_get_width(icon))
        let height = Int(frida_icon_get_height(icon))
        let bitsPerComponent = 8
        let bitsPerPixel = 4 * bitsPerComponent
        let bytesPerRow = width * (bitsPerPixel / 8)
        let colorSpace = CGColorSpaceCreateDeviceRGB()
        let bitmapInfo: CGBitmapInfo = [.byteOrder32Big, CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedLast.rawValue)]

        let pixels = frida_icon_get_pixels(icon)
        var size: gsize = 0
        let data = g_bytes_get_data(pixels, &size)!
        let provider = CGDataProvider(dataInfo: UnsafeMutableRawPointer(g_bytes_ref(pixels)), data: data, size: Int(size), releaseData: { info, data, size in
            g_bytes_unref(OpaquePointer(info))
        })!

        let shouldInterpolate = false
        let renderingIntent = CGColorRenderingIntent.defaultIntent

        let image = CGImage(width: width, height: height, bitsPerComponent: bitsPerComponent, bitsPerPixel: bitsPerPixel, bytesPerRow: bytesPerRow, space: colorSpace, bitmapInfo: bitmapInfo, provider: provider, decode: nil, shouldInterpolate: shouldInterpolate, intent: renderingIntent)!

        return NSImage(cgImage: image, size: NSSize(width: width, height: height))
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
}
