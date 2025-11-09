import Frida_Private

extension GLib {
    public final class MainLoop: CustomStringConvertible {
        internal let handle: OpaquePointer

        public init() {
            self.handle = g_main_loop_new(nil, 0)
        }

        deinit {
            g_main_loop_unref(handle)
        }

        public var description: String {
            "Frida.MainLoop()"
        }

        public func run() {
            g_main_loop_run(handle)
        }
    }
}
