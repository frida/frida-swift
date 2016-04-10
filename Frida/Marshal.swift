import CFrida

class Marshal {
    static func takeNativeError(error: UnsafeMutablePointer<GError>) -> Error {
        let code = FridaError(UInt32(error.memory.code))
        let message = String.fromCString(error.memory.message)!

        g_error_free(error)

        switch code {
        case FRIDA_ERROR_SERVER_NOT_RUNNING:
            return Error.ServerNotRunning(message)
        case FRIDA_ERROR_EXECUTABLE_NOT_FOUND:
            return Error.ExecutableNotFound(message)
        case FRIDA_ERROR_EXECUTABLE_NOT_SUPPORTED:
            return Error.ExecutableNotSupported(message)
        case FRIDA_ERROR_PROCESS_NOT_FOUND:
            return Error.ProcessNotFound(message)
        case FRIDA_ERROR_PROCESS_NOT_RESPONDING:
            return Error.ProcessNotResponding(message)
        case FRIDA_ERROR_INVALID_ARGUMENT:
            return Error.InvalidArgument(message)
        case FRIDA_ERROR_INVALID_OPERATION:
            return Error.InvalidOperation(message)
        case FRIDA_ERROR_PERMISSION_DENIED:
            return Error.PermissionDenied(message)
        case FRIDA_ERROR_ADDRESS_IN_USE:
            return Error.AddressInUse(message)
        case FRIDA_ERROR_TIMED_OUT:
            return Error.TimedOut(message)
        case FRIDA_ERROR_NOT_SUPPORTED:
            return Error.NotSupported(message)
        case FRIDA_ERROR_PROTOCOL:
            return Error.ProtocolViolation(message)
        case FRIDA_ERROR_TRANSPORT:
            return Error.Transport(message)
        default:
            fatalError("Unexpected Frida error code")
        }
    }

    static func imageFromIcon(icon: COpaquePointer) -> NSImage? {
        if icon == nil {
            return nil
        }

        let width = Int(frida_icon_get_width(icon))
        let height = Int(frida_icon_get_height(icon))
        let bitsPerComponent = 8
        let bitsPerPixel = 4 * bitsPerComponent
        let bytesPerRow = width * (bitsPerPixel / 8)
        let colorSpace = CGColorSpaceCreateDeviceRGB()
        let bitmapInfo: CGBitmapInfo = [.ByteOrder32Big, CGBitmapInfo(rawValue: CGImageAlphaInfo.PremultipliedLast.rawValue)]

        var size: Int32 = 0
        let pixels = frida_icon_get_pixels(icon, &size)
        let provider = CGDataProviderCreateWithData(g_object_ref(gpointer(icon)), pixels, Int(size), { info, data, size in
            g_object_unref(info)
        })

        let shouldInterpolate = false
        let renderingIntent = CGColorRenderingIntent.RenderingIntentDefault

        let image = CGImageCreate(width, height, bitsPerComponent, bitsPerPixel, bytesPerRow, colorSpace, bitmapInfo, provider, nil, shouldInterpolate, renderingIntent)!

        return NSImage(CGImage: image, size: NSSize(width: width, height: height))
    }
}
