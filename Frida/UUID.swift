import Frida_Private

public enum UUID4 {
    public static func stringRandom() -> String {
        let cstr = g_uuid_string_random()!
        let result = Marshal.stringFromCString(cstr)
        g_free(cstr)
        return result
    }
}
