import CFrida

class Marshal {
    static func takeNativeError(_ error: UnsafeMutablePointer<GError>) -> Error {
        let code = CFrida.FridaError.init(UInt32(error.pointee.code))
        let message = String(cString: error.pointee.message)

        g_error_free(error)

        switch code {
        case FRIDA_ERROR_SERVER_NOT_RUNNING:
            return FridaError.serverNotRunning(message)
        case FRIDA_ERROR_EXECUTABLE_NOT_FOUND:
            return FridaError.executableNotFound(message)
        case FRIDA_ERROR_EXECUTABLE_NOT_SUPPORTED:
            return FridaError.executableNotSupported(message)
        case FRIDA_ERROR_PROCESS_NOT_FOUND:
            return FridaError.processNotFound(message)
        case FRIDA_ERROR_PROCESS_NOT_RESPONDING:
            return FridaError.processNotResponding(message)
        case FRIDA_ERROR_INVALID_ARGUMENT:
            return FridaError.invalidArgument(message)
        case FRIDA_ERROR_INVALID_OPERATION:
            return FridaError.invalidOperation(message)
        case FRIDA_ERROR_PERMISSION_DENIED:
            return FridaError.permissionDenied(message)
        case FRIDA_ERROR_ADDRESS_IN_USE:
            return FridaError.addressInUse(message)
        case FRIDA_ERROR_TIMED_OUT:
            return FridaError.timedOut(message)
        case FRIDA_ERROR_NOT_SUPPORTED:
            return FridaError.notSupported(message)
        case FRIDA_ERROR_PROTOCOL:
            return FridaError.protocolViolation(message)
        case FRIDA_ERROR_TRANSPORT:
            return FridaError.transport(message)
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
}
