import CFrida

class Bytes {
    let buffer: Data

    private init(_ buffer: Data) {
        self.buffer = buffer
    }

    class func fromData(buffer: Data?) -> OpaquePointer! {
        if let buffer = buffer {
            let wrapper = Bytes(buffer)
            return buffer.withUnsafeBytes { data -> OpaquePointer in
                return g_bytes_new_with_free_func(data, gsize(buffer.count), { data in
                    _ = Unmanaged<Bytes>.fromOpaque(data!).takeRetainedValue()
                }, Unmanaged.passRetained(wrapper).toOpaque())
            }
        } else {
            return nil
        }
    }
}
