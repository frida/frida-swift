import Frida_Private

extension GLib {
    public enum UUID {
        public static func stringRandom() -> String {
            let cstr = g_uuid_string_random()!
            let result = Marshal.stringFromCString(cstr)
            g_free(cstr)
            return result
        }
    }
}
