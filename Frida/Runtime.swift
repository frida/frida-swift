import CFrida

class Runtime {
    typealias Handler = @convention(block) () -> Void

    static func scheduleOnMainThread(handler: Handler) {
        dispatch_async(dispatch_get_main_queue(), handler)
    }

    static func scheduleOnFridaThread(handler: Handler) {
        let data = gpointer(Unmanaged.passRetained(ScheduledOperation(handler: handler)).toOpaque())
        let source = g_idle_source_new()
        g_source_set_callback(source, { data in
            let operation = Unmanaged<ScheduledOperation>.fromOpaque(COpaquePointer(data)).takeRetainedValue()
            operation.handler()
            return gboolean(0)
        }, data, nil)
        g_source_attach(source, frida_get_main_context())
        g_source_unref(source)
    }

    private class ScheduledOperation {
        private let handler: Handler

        init(handler: Handler) {
            self.handler = handler
        }
    }
}
