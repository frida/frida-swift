internal import FridaCore

extension GLib {
    public enum Environment {
        public static var userCacheDir: String {
            Runtime.ensureInitialized()
            return String(cString: g_get_user_cache_dir())
        }
    }
}
