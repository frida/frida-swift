import CFrida

@objc(FridaDevice)
public class Device: NSObject, NSCopying {
    public weak var delegate: DeviceDelegate?

    public enum Kind {
        case local
        case remote
        case usb
    }

    public typealias GetFrontmostApplicationComplete = (_ result: GetFrontmostApplicationResult) -> Void
    public typealias GetFrontmostApplicationResult = () throws -> ApplicationDetails?

    public typealias EnumerateApplicationsComplete = (_ result: EnumerateApplicationsResult) -> Void
    public typealias EnumerateApplicationsResult = () throws -> [ApplicationDetails]

    public typealias EnumerateProcessesComplete = (_ result: EnumerateProcessesResult) -> Void
    public typealias EnumerateProcessesResult = () throws -> [ProcessDetails]

    public typealias EnableSpawnGatingComplete = (_ result: EnableSpawnGatingResult) -> Void
    public typealias EnableSpawnGatingResult = () throws -> Bool

    public typealias DisableSpawnGatingComplete = (_ result: DisableSpawnGatingResult) -> Void
    public typealias DisableSpawnGatingResult = () throws -> Bool

    public typealias EnumeratePendingSpawnComplete = (_ result: EnumeratePendingSpawnResult) -> Void
    public typealias EnumeratePendingSpawnResult = () throws -> [SpawnDetails]

    public typealias SpawnComplete = (_ result: SpawnResult) -> Void
    public typealias SpawnResult = () throws -> UInt

    public typealias InputComplete = (_ result: InputResult) -> Void
    public typealias InputResult = () throws -> Bool

    public typealias ResumeComplete = (_ result: ResumeResult) -> Void
    public typealias ResumeResult = () throws -> Bool

    public typealias KillComplete = (_ result: KillResult) -> Void
    public typealias KillResult = () throws -> Bool

    public typealias AttachComplete = (_ result: AttachResult) -> Void
    public typealias AttachResult = () throws -> Session

    private typealias SpawnAddedHandler = @convention(c) (_ device: OpaquePointer, _ spawn: OpaquePointer, _ userData: gpointer) -> Void
    private typealias SpawnRemovedHandler = @convention(c) (_ device: OpaquePointer, _ spawn: OpaquePointer, _ userData: gpointer) -> Void
    private typealias OutputHandler = @convention(c) (_ device: OpaquePointer, _ pid: guint, _ fd: gint,
        _ data: UnsafePointer<guint8>, _ dataSize: gint, _ userData: gpointer) -> Void
    private typealias LostHandler = @convention(c) (_ device: OpaquePointer, _ userData: gpointer) -> Void

    private let handle: OpaquePointer
    private var onSpawnAddedHandler: gulong = 0
    private var onSpawnRemovedHandler: gulong = 0
    private var onOutputHandler: gulong = 0
    private var onLostHandler: gulong = 0

    init(handle: OpaquePointer) {
        self.handle = handle

        super.init()

        let rawHandle = gpointer(handle)
        onSpawnAddedHandler = g_signal_connect_data(rawHandle, "spawn-added", unsafeBitCast(onSpawnAdded, to: GCallback.self),
                                                    gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                    releaseConnection, GConnectFlags(0))
        onSpawnRemovedHandler = g_signal_connect_data(rawHandle, "spawn-removed", unsafeBitCast(onSpawnRemoved, to: GCallback.self),
                                                      gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                      releaseConnection, GConnectFlags(0))
        onOutputHandler = g_signal_connect_data(rawHandle, "output", unsafeBitCast(onOutput, to: GCallback.self),
                                                gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                releaseConnection, GConnectFlags(0))
        onLostHandler = g_signal_connect_data(rawHandle, "lost", unsafeBitCast(onLost, to: GCallback.self),
                                              gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                              releaseConnection, GConnectFlags(0))
    }

    public func copy(with zone: NSZone?) -> Any {
        g_object_ref(gpointer(handle))
        return Device(handle: handle)
    }

    deinit {
        let rawHandle = gpointer(handle)
        let handlers = [onSpawnAddedHandler, onSpawnRemovedHandler, onOutputHandler, onLostHandler]
        Runtime.scheduleOnFridaThread {
            for handler in handlers {
                g_signal_handler_disconnect(rawHandle, handler)
            }
            g_object_unref(rawHandle)
        }
    }

    public var id: String {
        return String(cString: frida_device_get_id(handle))
    }

    public var name: String {
        return String(cString: frida_device_get_name(handle))
    }

    public var icon: NSImage? {
        return Marshal.imageFromIcon(frida_device_get_icon(handle))
    }

    public var kind: Kind {
        switch frida_device_get_dtype(handle) {
        case FRIDA_DEVICE_TYPE_LOCAL:
            return Kind.local
        case FRIDA_DEVICE_TYPE_REMOTE:
            return Kind.remote
        case FRIDA_DEVICE_TYPE_USB:
            return Kind.usb
        default:
            fatalError("Unexpected Frida Device kind")
        }
    }

    public override var description: String {
        return "Frida.Device(id: \"\(id)\", name: \"\(name)\", kind: \"\(kind)\")"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        if let device = object as? Device {
            return device.handle == handle
        } else {
            return false
        }
    }

    public override var hash: Int {
        return handle.hashValue
    }

    public func getFrontmostApplication(_ completionHandler: @escaping GetFrontmostApplicationComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_get_frontmost_application(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<GetFrontmostApplicationComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawApplication = frida_device_get_frontmost_application_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let application: ApplicationDetails? = rawApplication != nil ? ApplicationDetails(handle: rawApplication!) : nil

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { application }
                }
            }, Unmanaged.passRetained(AsyncOperation<GetFrontmostApplicationComplete>(completionHandler)).toOpaque())
        }
    }

    public func enumerateApplications(_ completionHandler: @escaping EnumerateApplicationsComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_enumerate_applications(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnumerateApplicationsComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawApplications = frida_device_enumerate_applications_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
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
            }, Unmanaged.passRetained(AsyncOperation<EnumerateApplicationsComplete>(completionHandler)).toOpaque())
        }
    }

    public func enumerateProcesses(_ completionHandler: @escaping EnumerateProcessesComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_enumerate_processes(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnumerateProcessesComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawProcesses = frida_device_enumerate_processes_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
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
            }, Unmanaged.passRetained(AsyncOperation<EnumerateProcessesComplete>(completionHandler)).toOpaque())
        }
    }

    public func enableSpawnGating(_ completionHandler: @escaping EnableSpawnGatingComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_device_enable_spawn_gating(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnableSpawnGatingComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_device_enable_spawn_gating_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, Unmanaged.passRetained(AsyncOperation<EnableSpawnGatingComplete>(completionHandler)).toOpaque())
        }
    }

    public func disableSpawnGating(_ completionHandler: @escaping DisableSpawnGatingComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_device_disable_spawn_gating(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<DisableSpawnGatingComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_device_disable_spawn_gating_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, Unmanaged.passRetained(AsyncOperation<DisableSpawnGatingComplete>(completionHandler)).toOpaque())
        }
    }

    public func enumeratePendingSpawn(_ completionHandler: @escaping EnumeratePendingSpawnComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_enumerate_pending_spawn(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnumeratePendingSpawnComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawSpawn = frida_device_enumerate_pending_spawn_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                var spawn = [SpawnDetails]()
                let numberOfSpawn = frida_spawn_list_size(rawSpawn)
                for index in 0..<numberOfSpawn {
                    let details = SpawnDetails(handle: frida_spawn_list_get(rawSpawn, index))
                    spawn.append(details)
                }
                g_object_unref(gpointer(rawSpawn))

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { spawn }
                }
            }, Unmanaged.passRetained(AsyncOperation<EnumeratePendingSpawnComplete>(completionHandler)).toOpaque())
        }
    }

    public func spawn(_ program: String, argv: [String]? = nil, envp: [String: String]? = nil, env: [String: String]? = nil,
                      cwd: String? = nil, stdio: Stdio? = nil, completionHandler: @escaping SpawnComplete) {
        Runtime.scheduleOnFridaThread {
            let options = frida_spawn_options_new()

            let (rawArgv, argvLength) = Marshal.strvFromArray(argv)
            if let rawArgv = rawArgv {
                frida_spawn_options_set_argv(options, rawArgv, argvLength)
                g_strfreev(rawArgv)
            }

            let (rawEnvp, envpLength) = Marshal.envpFromDictionary(envp)
            if let rawEnvp = rawEnvp {
                frida_spawn_options_set_envp(options, rawEnvp, envpLength)
                g_strfreev(rawEnvp)
            }

            let (rawEnv, envLength) = Marshal.envpFromDictionary(env)
            if let rawEnv = rawEnv {
                frida_spawn_options_set_env(options, rawEnv, envLength)
                g_strfreev(rawEnv)
            }

            if let cwd = cwd {
                frida_spawn_options_set_cwd(options, cwd)
            }

            if let stdio = stdio {
                frida_spawn_options_set_stdio(options, FridaStdio(UInt32(stdio.rawValue)))
            }

            frida_device_spawn(self.handle, program, options, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<SpawnComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let pid = frida_device_spawn_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { UInt(pid) }
                }
            }, Unmanaged.passRetained(AsyncOperation<SpawnComplete>(completionHandler)).toOpaque())

            g_object_unref(gpointer(options))
        }
    }

    public func input(_ pid: UInt, data: Data, completionHandler: @escaping InputComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            let rawData = Bytes.fromData(buffer: data)
            frida_device_input(self.handle, guint(pid), rawData, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<InputComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_device_input_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, Unmanaged.passRetained(AsyncOperation<InputComplete>(completionHandler)).toOpaque())
            g_bytes_unref(rawData)
        }
    }

    public func resume(_ pid: UInt, completionHandler: @escaping ResumeComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_device_resume(self.handle, guint(pid), nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<ResumeComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_device_resume_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, Unmanaged.passRetained(AsyncOperation<ResumeComplete>(completionHandler)).toOpaque())
        }
    }

    public func kill(_ pid: UInt, completionHandler: @escaping KillComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            frida_device_kill(self.handle, guint(pid), nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<KillComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_device_kill_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { true }
                }
            }, Unmanaged.passRetained(AsyncOperation<KillComplete>(completionHandler)).toOpaque())
        }
    }

    public func attach(_ pid: UInt, completionHandler: @escaping AttachComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_attach(self.handle, guint(pid), nil, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<AttachComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawSession = frida_device_attach_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let session = Session(handle: rawSession!)

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { session }
                }
            }, Unmanaged.passRetained(AsyncOperation<AttachComplete>(completionHandler)).toOpaque())
        }
    }

    private let onSpawnAdded: SpawnAddedHandler = { _, rawSpawn, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawSpawn))
        let spawn = SpawnDetails(handle: rawSpawn)

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device?(device, didAddSpawn: spawn)
            }
        }
    }

    private let onSpawnRemoved: SpawnRemovedHandler = { _, rawSpawn, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawSpawn))
        let spawn = SpawnDetails(handle: rawSpawn)

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device?(device, didRemoveSpawn: spawn)
            }
        }
    }

    private let onOutput: OutputHandler = { _, pid, fd, rawData, rawDataSize, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        let data = Data(bytes: UnsafePointer<UInt8>(rawData), count: Int(rawDataSize))

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device?(device, didOutput: data, toFileDescriptor: Int(fd), fromProcess: UInt(pid))
            }
        }
    }

    private let onLost: LostHandler = { _, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.deviceLost?(device)
            }
        }
    }

    private let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<Device>>.fromOpaque(data!).release()
    }
}

@objc(FridaStdio)
public enum Stdio: Int, CustomStringConvertible {
    case inherit
    case pipe

    public var description: String {
        switch self {
        case .inherit: return "inherit"
        case .pipe: return "pipe"
        }
    }
}
