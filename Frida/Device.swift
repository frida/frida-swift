import CFrida

@objc(FridaDevice)
public class Device: NSObject, NSCopying {
    public var delegate: DeviceDelegate?

    public enum Kind {
        case Local
        case Tether
        case Remote
    }

    public typealias GetFrontmostApplicationComplete = (result: GetFrontmostApplicationResult) -> Void
    public typealias GetFrontmostApplicationResult = () throws -> ApplicationDetails?

    public typealias EnumerateApplicationsComplete = (result: EnumerateApplicationsResult) -> Void
    public typealias EnumerateApplicationsResult = () throws -> [ApplicationDetails]

    public typealias EnumerateProcessesComplete = (result: EnumerateProcessesResult) -> Void
    public typealias EnumerateProcessesResult = () throws -> [ProcessDetails]

    public typealias EnableSpawnGatingComplete = (result: EnableSpawnGatingResult) -> Void
    public typealias EnableSpawnGatingResult = () throws -> Bool

    public typealias DisableSpawnGatingComplete = (result: DisableSpawnGatingResult) -> Void
    public typealias DisableSpawnGatingResult = () throws -> Bool

    public typealias EnumeratePendingSpawnsComplete = (result: EnumeratePendingSpawnsResult) -> Void
    public typealias EnumeratePendingSpawnsResult = () throws -> [SpawnDetails]

    public typealias SpawnComplete = (result: SpawnResult) -> Void
    public typealias SpawnResult = () throws -> UInt

    public typealias InputComplete = (result: InputResult) -> Void
    public typealias InputResult = () throws -> Bool

    public typealias ResumeComplete = (result: ResumeResult) -> Void
    public typealias ResumeResult = () throws -> Bool

    public typealias KillComplete = (result: KillResult) -> Void
    public typealias KillResult = () throws -> Bool

    public typealias AttachComplete = (result: AttachResult) -> Void
    public typealias AttachResult = () throws -> Session

    private typealias SpawnedHandler = @convention(c) (device: COpaquePointer, spawn: COpaquePointer, userData: gpointer) -> Void
    private typealias OutputHandler = @convention(c) (device: COpaquePointer, pid: guint, fd: gint,
        data: UnsafePointer<guint8>, dataSize: gint, userData: gpointer) -> Void
    private typealias LostHandler = @convention(c) (device: COpaquePointer, userData: gpointer) -> Void

    private let handle: COpaquePointer
    private var onSpawnedHandler: gulong = 0
    private var onOutputHandler: gulong = 0
    private var onLostHandler: gulong = 0

    init(handle: COpaquePointer) {
        self.handle = handle

        super.init()

        let rawHandle = gpointer(handle)
        onSpawnedHandler = g_signal_connect_data(rawHandle, "spawned", unsafeBitCast(onSpawned, GCallback.self),
                                                 gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                 releaseConnection, GConnectFlags(0))
        onOutputHandler = g_signal_connect_data(rawHandle, "output", unsafeBitCast(onOutput, GCallback.self),
                                                gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                releaseConnection, GConnectFlags(0))
        onLostHandler = g_signal_connect_data(rawHandle, "lost", unsafeBitCast(onLost, GCallback.self),
                                              gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                              releaseConnection, GConnectFlags(0))
    }

    public func copyWithZone(zone: NSZone) -> AnyObject {
        g_object_ref(gpointer(handle))
        return Device(handle: handle)
    }

    deinit {
        let rawHandle = gpointer(handle)
        let handlers = [onSpawnedHandler, onOutputHandler, onLostHandler]
        Runtime.scheduleOnFridaThread {
            for handler in handlers {
                g_signal_handler_disconnect(rawHandle, handler)
            }
            g_object_unref(rawHandle)
        }
    }

    public var id: String {
        return String.fromCString(frida_device_get_id(handle))!
    }

    public var name: String {
        return String.fromCString(frida_device_get_name(handle))!
    }

    public var icon: NSImage? {
        return Marshal.imageFromIcon(frida_device_get_icon(handle))
    }

    public var kind: Kind {
        switch frida_device_get_dtype(handle) {
        case FRIDA_DEVICE_TYPE_LOCAL:
            return Kind.Local
        case FRIDA_DEVICE_TYPE_TETHER:
            return Kind.Tether
        case FRIDA_DEVICE_TYPE_REMOTE:
            return Kind.Remote
        default:
            fatalError("Unexpected Frida Device kind")
        }
    }

    public override var description: String {
        return "Frida.Device(id: \"\(id)\", name: \"\(name)\", kind: \"\(kind)\")"
    }

    public override func isEqual(object: AnyObject?) -> Bool {
        if let device = object as? Device {
            return device.handle == handle
        } else {
            return false
        }
    }

    public override var hash: Int {
        return handle.hashValue
    }

    public func getFrontmostApplication(completionHandler: GetFrontmostApplicationComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_get_frontmost_application(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<GetFrontmostApplicationComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                let rawApplication = frida_device_get_frontmost_application_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let application: ApplicationDetails? = rawApplication != nil ? ApplicationDetails(handle: rawApplication) : nil

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { application }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<GetFrontmostApplicationComplete>(completionHandler)).toOpaque()))
        }
    }

    public func enumerateApplications(completionHandler: EnumerateApplicationsComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_enumerate_applications(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnumerateApplicationsComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                let rawApplications = frida_device_enumerate_applications_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                var applications = [ApplicationDetails]()
                let numberOfApplications = frida_application_list_size(rawApplications)
                for index in 0..<numberOfApplications {
                    let application = ApplicationDetails(handle: frida_application_list_get(rawApplications, index))
                    applications.append(application)
                }
                g_object_unref(gpointer(rawApplications))

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { applications }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<EnumerateApplicationsComplete>(completionHandler)).toOpaque()))
        }
    }

    public func enumerateProcesses(completionHandler: EnumerateProcessesComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_enumerate_processes(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnumerateProcessesComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                let rawProcesses = frida_device_enumerate_processes_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                var processes = [ProcessDetails]()
                let numberOfProcesses = frida_process_list_size(rawProcesses)
                for index in 0..<numberOfProcesses {
                    let process = ProcessDetails(handle: frida_process_list_get(rawProcesses, index))
                    processes.append(process)
                }
                g_object_unref(gpointer(rawProcesses))

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { processes }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<EnumerateProcessesComplete>(completionHandler)).toOpaque()))
        }
    }

    public func enableSpawnGating(completionHandler: EnableSpawnGatingComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_device_enable_spawn_gating(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnableSpawnGatingComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                frida_device_enable_spawn_gating_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<EnableSpawnGatingComplete>(completionHandler)).toOpaque()))
        }
    }

    public func disableSpawnGating(completionHandler: DisableSpawnGatingComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_device_disable_spawn_gating(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<DisableSpawnGatingComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                frida_device_disable_spawn_gating_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<DisableSpawnGatingComplete>(completionHandler)).toOpaque()))
        }
    }

    public func enumeratePendingSpawns(completionHandler: EnumeratePendingSpawnsComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_enumerate_pending_spawns(self.handle, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnumeratePendingSpawnsComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                let rawSpawns = frida_device_enumerate_pending_spawns_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                var spawns = [SpawnDetails]()
                let numberOfSpawns = frida_spawn_list_size(rawSpawns)
                for index in 0..<numberOfSpawns {
                    let spawn = SpawnDetails(handle: frida_spawn_list_get(rawSpawns, index))
                    spawns.append(spawn)
                }
                g_object_unref(gpointer(rawSpawns))

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { spawns }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<EnumeratePendingSpawnsComplete>(completionHandler)).toOpaque()))
        }
    }

    public func spawn(path: String, argv: [String], envp: [String]? = nil, completionHandler: SpawnComplete) {
        Runtime.scheduleOnFridaThread {
            let rawArgv = unsafeBitCast(g_malloc0(gsize((argv.count + 1) * sizeof(gpointer))), UnsafeMutablePointer<UnsafeMutablePointer<gchar>>.self)
            for (index, arg) in argv.enumerate() {
                rawArgv.advancedBy(index).memory = g_strdup(arg)
            }

            var rawEnvp: UnsafeMutablePointer<UnsafeMutablePointer<gchar>>
            var envpLength: gint
            if let elements = envp {
                rawEnvp = unsafeBitCast(g_malloc0(gsize((elements.count + 1) * sizeof(gpointer))), UnsafeMutablePointer<UnsafeMutablePointer<gchar>>.self)
                for (index, env) in elements.enumerate() {
                    rawEnvp.advancedBy(index).memory = g_strdup(env)
                }
                envpLength = gint(elements.count)
            } else {
                rawEnvp = g_get_environ()
                envpLength = gint(g_strv_length(rawEnvp))
            }

            frida_device_spawn(self.handle, path, rawArgv, gint(argv.count), rawEnvp, envpLength, { source, result, data in
                let operation = Unmanaged<AsyncOperation<SpawnComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                let pid = frida_device_spawn_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { UInt(pid) }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<SpawnComplete>(completionHandler)).toOpaque()))

            g_strfreev(rawEnvp)
            g_strfreev(rawArgv)
        }
    }

    public func input(pid: UInt, data: NSData, completionHandler: InputComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            withExtendedLifetime(data) {
                frida_device_input(self.handle, guint(pid), UnsafeMutablePointer<guint8>(data.bytes), gint(data.length), { source, result, data in
                    let operation = Unmanaged<AsyncOperation<InputComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                    var rawError: UnsafeMutablePointer<GError> = nil
                    frida_device_input_finish(COpaquePointer(source), result, &rawError)
                    if rawError != nil {
                        let error = Marshal.takeNativeError(rawError)
                        Runtime.scheduleOnMainThread {
                            operation.completionHandler { throw error }
                        }
                        return
                    }

                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { true }
                    }
                }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<InputComplete>(completionHandler)).toOpaque()))
            }
        }
    }

    public func resume(pid: UInt, completionHandler: ResumeComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_device_resume(self.handle, guint(pid), { source, result, data in
                let operation = Unmanaged<AsyncOperation<ResumeComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                frida_device_resume_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<ResumeComplete>(completionHandler)).toOpaque()))
        }
    }

    public func kill(pid: UInt, completionHandler: KillComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_device_kill(self.handle, guint(pid), { source, result, data in
                let operation = Unmanaged<AsyncOperation<KillComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                frida_device_kill_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<KillComplete>(completionHandler)).toOpaque()))
        }
    }

    public func attach(pid: UInt, completionHandler: AttachComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_attach(self.handle, guint(pid), { source, result, data in
                let operation = Unmanaged<AsyncOperation<AttachComplete>>.fromOpaque(COpaquePointer(data)).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError> = nil
                let rawSession = frida_device_attach_finish(COpaquePointer(source), result, &rawError)
                if rawError != nil {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let session = Session(handle: rawSession)

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { session }
                }
            }, UnsafeMutablePointer(Unmanaged.passRetained(AsyncOperation<AttachComplete>(completionHandler)).toOpaque()))
        }
    }

    private let onSpawned: SpawnedHandler = { _, rawSpawn, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(COpaquePointer(userData)).takeUnretainedValue()

        g_object_ref(gpointer(rawSpawn))
        let spawn = SpawnDetails(handle: rawSpawn)

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device?(device, didSpawn: spawn)
            }
        }
    }

    private let onOutput: OutputHandler = { _, pid, fd, rawData, rawDataSize, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(COpaquePointer(userData)).takeUnretainedValue()

        let data = NSData(bytes: rawData, length: Int(rawDataSize))

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device?(device, didOutput: data, toFileDescriptor: Int(fd), fromProcess: UInt(pid))
            }
        }
    }

    private let onLost: LostHandler = { _, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(COpaquePointer(userData)).takeUnretainedValue()

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.deviceLost?(device)
            }
        }
    }

    private let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<Device>>.fromOpaque(COpaquePointer(data)).release()
    }
}
