import AppKit
import Frida_Private

@objc(FridaDevice)
public class Device: NSObject, NSCopying {
    public weak var delegate: DeviceDelegate?

    public enum Kind {
        case local
        case remote
        case usb
    }

    public typealias QuerySystemParametersComplete = (_ result: QuerySystemParametersResult) -> Void
    public typealias QuerySystemParametersResult = () throws -> [String: Any]

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

    public typealias EnumeratePendingChildrenComplete = (_ result: EnumeratePendingChildrenResult) -> Void
    public typealias EnumeratePendingChildrenResult = () throws -> [ChildDetails]

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

    public typealias InjectLibraryFileComplete = (_ result: InjectLibraryFileResult) -> Void
    public typealias InjectLibraryFileResult = () throws -> UInt

    public typealias InjectLibraryBlobComplete = (_ result: InjectLibraryBlobResult) -> Void
    public typealias InjectLibraryBlobResult = () throws -> UInt

    public typealias OpenChannelComplete = (_ result: OpenChannelResult) -> Void
    public typealias OpenChannelResult = () throws -> IOStream

    private typealias SpawnAddedHandler = @convention(c) (_ device: OpaquePointer, _ spawn: OpaquePointer, _ userData: gpointer) -> Void
    private typealias SpawnRemovedHandler = @convention(c) (_ device: OpaquePointer, _ spawn: OpaquePointer, _ userData: gpointer) -> Void
    private typealias ChildAddedHandler = @convention(c) (_ device: OpaquePointer, _ child: OpaquePointer, _ userData: gpointer) -> Void
    private typealias ChildRemovedHandler = @convention(c) (_ device: OpaquePointer, _ child: OpaquePointer, _ userData: gpointer) -> Void
    private typealias ProcessCrashedHandler = @convention(c) (_ device: OpaquePointer, _ crash: OpaquePointer, _ userData: gpointer) -> Void
    private typealias OutputHandler = @convention(c) (_ device: OpaquePointer, _ pid: guint, _ fd: gint,
        _ data: UnsafePointer<guint8>, _ dataSize: gint, _ userData: gpointer) -> Void
    private typealias UninjectedHandler = @convention(c) (_ device: OpaquePointer, _ id: guint, _ userData: gpointer) -> Void
    private typealias LostHandler = @convention(c) (_ device: OpaquePointer, _ userData: gpointer) -> Void

    private let handle: OpaquePointer
    private var onSpawnAddedHandler: gulong = 0
    private var onSpawnRemovedHandler: gulong = 0
    private var onChildAddedHandler: gulong = 0
    private var onChildRemovedHandler: gulong = 0
    private var onProcessCrashedHandler: gulong = 0
    private var onOutputHandler: gulong = 0
    private var onUninjectedHandler: gulong = 0
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
        onChildAddedHandler = g_signal_connect_data(rawHandle, "child-added", unsafeBitCast(onChildAdded, to: GCallback.self),
                                                    gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                    releaseConnection, GConnectFlags(0))
        onChildRemovedHandler = g_signal_connect_data(rawHandle, "child-removed", unsafeBitCast(onChildRemoved, to: GCallback.self),
                                                      gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                      releaseConnection, GConnectFlags(0))
        onProcessCrashedHandler = g_signal_connect_data(rawHandle, "process-crashed", unsafeBitCast(onProcessCrashed, to: GCallback.self),
                                                        gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                        releaseConnection, GConnectFlags(0))
        onOutputHandler = g_signal_connect_data(rawHandle, "output", unsafeBitCast(onOutput, to: GCallback.self),
                                                gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                                                releaseConnection, GConnectFlags(0))
        onUninjectedHandler = g_signal_connect_data(rawHandle, "uninjected", unsafeBitCast(onUninjected, to: GCallback.self),
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
        let handlers = [onSpawnAddedHandler, onSpawnRemovedHandler, onChildAddedHandler, onChildRemovedHandler, onProcessCrashedHandler,
                        onOutputHandler, onUninjectedHandler, onLostHandler]
        Runtime.scheduleOnFridaThread {
            for handler in handlers {
                g_signal_handler_disconnect(rawHandle, handler)
            }
            g_object_unref(rawHandle)
        }
    }

    @objc public var id: String {
        return String(cString: frida_device_get_id(handle))
    }

    @objc public var name: String {
        return String(cString: frida_device_get_name(handle))
    }

    @objc public lazy var icon: NSImage? = {
        guard let iconVariant = frida_device_get_icon(handle) else {
            return nil
        }
        let iconDict = Marshal.valueFromVariant(iconVariant) as! [String: Any];
        return Marshal.iconFromVarDict(iconDict)
    }()

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

    public lazy var bus: Bus = {
        let busHandle = frida_device_get_bus(handle)!
        g_object_ref(gpointer(busHandle))
        return Bus(handle: busHandle)
    }()

    public var isLost: Bool {
        return frida_device_is_lost(handle) != 0
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

    public func querySystemParameters(_ completionHandler: @escaping QuerySystemParametersComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_query_system_parameters(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<QuerySystemParametersComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawParameters = frida_device_query_system_parameters_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let parameters = Marshal.dictionaryFromParametersDict(rawParameters!)

                g_hash_table_unref(rawParameters!)

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { parameters }
                }
            }, Unmanaged.passRetained(AsyncOperation<QuerySystemParametersComplete>(completionHandler)).toOpaque())
        }
    }

    public func getFrontmostApplication(scope: Scope? = nil, _ completionHandler: @escaping GetFrontmostApplicationComplete) {
        Runtime.scheduleOnFridaThread {
            let options = frida_frontmost_query_options_new()
            defer {
                g_object_unref(gpointer(options))
            }

            if let scope = scope {
                frida_frontmost_query_options_set_scope(options, FridaScope(scope.rawValue))
            }

            frida_device_get_frontmost_application(self.handle, options, nil, { source, result, data in
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

    public func enumerateApplications(identifiers: [String]? = nil, scope: Scope? = nil, _ completionHandler: @escaping EnumerateApplicationsComplete) {
        Runtime.scheduleOnFridaThread {
            let options = frida_application_query_options_new()
            defer {
                g_object_unref(gpointer(options))
            }

            for identifier in identifiers ?? [] {
                frida_application_query_options_select_identifier(options, identifier)
            }

            if let scope = scope {
                frida_application_query_options_set_scope(options, FridaScope(scope.rawValue))
            }

            frida_device_enumerate_applications(self.handle, options, nil, { source, result, data in
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

                var applications: [ApplicationDetails] = []
                let n = frida_application_list_size(rawApplications)
                for i in 0..<n {
                    let application = ApplicationDetails(handle: frida_application_list_get(rawApplications, i))
                    applications.append(application)
                }
                g_object_unref(gpointer(rawApplications))

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { applications }
                }
            }, Unmanaged.passRetained(AsyncOperation<EnumerateApplicationsComplete>(completionHandler)).toOpaque())
        }
    }

    public func enumerateProcesses(pids: [UInt]? = nil, scope: Scope? = nil, _ completionHandler: @escaping EnumerateProcessesComplete) {
        Runtime.scheduleOnFridaThread {
            let options = frida_process_query_options_new()
            defer {
                g_object_unref(gpointer(options))
            }

            for pid in pids ?? [] {
                frida_process_query_options_select_pid(options, guint(pid))
            }

            if let scope = scope {
                frida_process_query_options_set_scope(options, FridaScope(scope.rawValue))
            }

            frida_device_enumerate_processes(self.handle, options, nil, { source, result, data in
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

                var processes: [ProcessDetails] = []
                let n = frida_process_list_size(rawProcesses)
                for i in 0..<n {
                    let process = ProcessDetails(handle: frida_process_list_get(rawProcesses, i))
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

                var spawn: [SpawnDetails] = []
                let n = frida_spawn_list_size(rawSpawn)
                for i in 0..<n {
                    let details = SpawnDetails(handle: frida_spawn_list_get(rawSpawn, i))
                    spawn.append(details)
                }
                g_object_unref(gpointer(rawSpawn))

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { spawn }
                }
            }, Unmanaged.passRetained(AsyncOperation<EnumeratePendingSpawnComplete>(completionHandler)).toOpaque())
        }
    }

    public func enumeratePendingChildren(_ completionHandler: @escaping EnumeratePendingChildrenComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_enumerate_pending_children(self.handle, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<EnumeratePendingChildrenComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawChildren = frida_device_enumerate_pending_children_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                var children: [ChildDetails] = []
                let n = frida_child_list_size(rawChildren)
                for i in 0..<n {
                    let details = ChildDetails(handle: frida_child_list_get(rawChildren, i))
                    children.append(details)
                }
                g_object_unref(gpointer(rawChildren))

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { children }
                }
            }, Unmanaged.passRetained(AsyncOperation<EnumeratePendingChildrenComplete>(completionHandler)).toOpaque())
        }
    }

    public func spawn(_ program: String, argv: [String]? = nil, envp: [String: String]? = nil, env: [String: String]? = nil,
                      cwd: String? = nil, stdio: Stdio? = nil, completionHandler: @escaping SpawnComplete) {
        Runtime.scheduleOnFridaThread {
            let options = frida_spawn_options_new()
            defer {
                g_object_unref(gpointer(options))
            }

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
                frida_spawn_options_set_stdio(options, FridaStdio(stdio.rawValue))
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
        }
    }

    public func input(_ pid: UInt, data: Data, completionHandler: @escaping InputComplete = { _ in }) {
        Runtime.scheduleOnFridaThread {
            let rawData = Marshal.bytesFromData(data)
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

    public func attach(to pid: UInt, realm: Realm? = nil, persistTimeout: UInt? = nil, completionHandler: @escaping AttachComplete) {
        Runtime.scheduleOnFridaThread {
            let options = frida_session_options_new()
            defer {
                g_object_unref(gpointer(options))
            }

            if let realm = realm {
                frida_session_options_set_realm(options, FridaRealm(realm.rawValue))
            }

            if let persistTimeout = persistTimeout {
                frida_session_options_set_persist_timeout(options, guint(persistTimeout))
            }

            frida_device_attach(self.handle, guint(pid), options, nil, { source, result, data in
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

    public func injectLibraryFileFile(into pid: UInt, path: String, entrypoint: String, data: String, completionHandler: @escaping InjectLibraryFileComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_inject_library_file(self.handle, guint(pid), path, entrypoint, data, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<InjectLibraryFileComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawId = frida_device_inject_library_file_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let id = UInt(rawId)

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { id }
                }
            }, Unmanaged.passRetained(AsyncOperation<InjectLibraryFileComplete>(completionHandler)).toOpaque())
        }
    }

    public func injectLibraryBlobBlob(into pid: UInt, blob: Data, entrypoint: String, data: String, completionHandler: @escaping InjectLibraryBlobComplete) {
        Runtime.scheduleOnFridaThread {
            let rawBlob = Marshal.bytesFromData(blob)
            frida_device_inject_library_blob(self.handle, guint(pid), rawBlob, entrypoint, data, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<InjectLibraryBlobComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawId = frida_device_inject_library_blob_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let id = UInt(rawId)

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { id }
                }
            }, Unmanaged.passRetained(AsyncOperation<InjectLibraryBlobComplete>(completionHandler)).toOpaque())
            g_bytes_unref(rawBlob)
        }
    }

    public func openChannel(_ address: String, completionHandler: @escaping OpenChannelComplete) {
        Runtime.scheduleOnFridaThread {
            frida_device_open_channel(self.handle, address, nil, { source, result, data in
                let operation = Unmanaged<AsyncOperation<OpenChannelComplete>>.fromOpaque(data!).takeRetainedValue()

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawStream = frida_device_open_channel_finish(OpaquePointer(source), result, &rawError)
                if let rawError = rawError {
                    let error = Marshal.takeNativeError(rawError)
                    Runtime.scheduleOnMainThread {
                        operation.completionHandler { throw error }
                    }
                    return
                }

                let stream = IOStream(handle: rawStream!)

                Runtime.scheduleOnMainThread {
                    operation.completionHandler { stream }
                }
            }, Unmanaged.passRetained(AsyncOperation<OpenChannelComplete>(completionHandler)).toOpaque())
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

    private let onChildAdded: ChildAddedHandler = { _, rawChild, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawChild))
        let child = ChildDetails(handle: rawChild)

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device?(device, didAddChild: child)
            }
        }
    }

    private let onChildRemoved: ChildRemovedHandler = { _, rawChild, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawChild))
        let child = ChildDetails(handle: rawChild)

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device?(device, didRemoveChild: child)
            }
        }
    }

    private let onProcessCrashed: ProcessCrashedHandler = { _, rawCrash, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawCrash))
        let crash = CrashDetails(handle: rawCrash)

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device?(device, didObserveCrash: crash)
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

    private let onUninjected: UninjectedHandler = { _, id, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device?(device, didUninject: UInt(id))
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

@objc(FridaScope)
public enum Scope: UInt32, CustomStringConvertible {
    case minimal
    case metadata
    case full

    public var description: String {
        switch self {
        case .minimal: return "minimal"
        case .metadata: return "metadata"
        case .full: return "full"
        }
    }
}

@objc(FridaStdio)
public enum Stdio: UInt32, CustomStringConvertible {
    case inherit
    case pipe

    public var description: String {
        switch self {
        case .inherit: return "inherit"
        case .pipe: return "pipe"
        }
    }
}

@objc(FridaRealm)
public enum Realm: UInt32, CustomStringConvertible {
    case native
    case emulated

    public var description: String {
        switch self {
        case .native: return "native"
        case .emulated: return "emulated"
        }
    }
}
