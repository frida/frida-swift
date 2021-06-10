import CFrida

class Bytes {
    let buffer: Data

    private init(_ buffer: Data) {
        self.buffer = buffer
    }

    class func fromData(buffer: Data?) -> OpaquePointer! {
        if let buffer = buffer {
            return buffer.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
                return g_bytes_new(ptr.baseAddress, UInt(ptr.count))
            }
        } else {
            return nil
        }
    }
}
