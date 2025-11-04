import Frida_Private

public final class Device: CustomStringConvertible, Equatable, Hashable, Identifiable {
    public weak var delegate: (any DeviceDelegate)?

    @frozen
    public enum Kind: UInt, CustomStringConvertible {
        case local
        case remote
        case usb

        public var description: String {
            switch self {
            case .local: return "local"
            case .remote: return "remote"
            case .usb: return "usb"
            }
        }
    }

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

    init(handle: OpaquePointer) {
        self.handle = handle

        let rawHandle = gpointer(handle)
        g_signal_connect_data(rawHandle, "spawn-added", unsafeBitCast(onSpawnAdded, to: GCallback.self),
                              gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                              releaseConnection, GConnectFlags(0))
        g_signal_connect_data(rawHandle, "spawn-removed", unsafeBitCast(onSpawnRemoved, to: GCallback.self),
                              gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                              releaseConnection, GConnectFlags(0))
        g_signal_connect_data(rawHandle, "child-added", unsafeBitCast(onChildAdded, to: GCallback.self),
                              gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                              releaseConnection, GConnectFlags(0))
        g_signal_connect_data(rawHandle, "child-removed", unsafeBitCast(onChildRemoved, to: GCallback.self),
                              gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                              releaseConnection, GConnectFlags(0))
        g_signal_connect_data(rawHandle, "process-crashed", unsafeBitCast(onProcessCrashed, to: GCallback.self),
                              gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                              releaseConnection, GConnectFlags(0))
        g_signal_connect_data(rawHandle, "output", unsafeBitCast(onOutput, to: GCallback.self),
                              gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                              releaseConnection, GConnectFlags(0))
        g_signal_connect_data(rawHandle, "uninjected", unsafeBitCast(onUninjected, to: GCallback.self),
                              gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                              releaseConnection, GConnectFlags(0))
        g_signal_connect_data(rawHandle, "lost", unsafeBitCast(onLost, to: GCallback.self),
                              gpointer(Unmanaged.passRetained(SignalConnection(instance: self)).toOpaque()),
                              releaseConnection, GConnectFlags(0))
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var id: String {
        return String(cString: frida_device_get_id(handle))
    }

    public var name: String {
        return String(cString: frida_device_get_name(handle))
    }

    public lazy var icon: Icon? = {
        guard let iconVariant = frida_device_get_icon(handle) else {
            return nil
        }
        let iconDict = Marshal.valueFromVariant(iconVariant) as! [String: Any]
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

    public var description: String {
        return "Frida.Device(id: \"\(id)\", name: \"\(name)\", kind: \"\(kind)\")"
    }

    public static func == (lhs: Device, rhs: Device) -> Bool {
        return lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }

    public func querySystemParameters() async throws -> [String: Any] {
        return try await fridaAsync([String: Any].self) { op in
            frida_device_query_system_parameters(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<[String: Any]>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawParameters = frida_device_query_system_parameters_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                let parameters = Marshal.dictionaryFromParametersDict(rawParameters!)
                g_hash_table_unref(rawParameters!)
                op.resumeSuccess(parameters)
            }, op.userData)
        }
    }

    public func getFrontmostApplication(scope: Scope? = nil) async throws -> ApplicationDetails? {
        return try await fridaAsync(ApplicationDetails?.self) { op in
            let options = frida_frontmost_query_options_new()

            if let scope {
                frida_frontmost_query_options_set_scope(options, FridaScope(scope.rawValue))
            }

            frida_device_get_frontmost_application(self.handle, options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<ApplicationDetails?>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawApplication = frida_device_get_frontmost_application_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                let application = rawApplication != nil ? ApplicationDetails(handle: rawApplication!) : nil
                op.resumeSuccess(application)
            }, op.userData)

            g_object_unref(gpointer(options))
        }
    }

    public func enumerateApplications(identifiers: [String]? = nil, scope: Scope? = nil) async throws -> [ApplicationDetails] {
        return try await fridaAsync([ApplicationDetails].self) { op in
            let options = frida_application_query_options_new()

            for identifier in identifiers ?? [] {
                frida_application_query_options_select_identifier(options, identifier)
            }

            if let scope {
                frida_application_query_options_set_scope(options, FridaScope(scope.rawValue))
            }

            frida_device_enumerate_applications(self.handle, options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<[ApplicationDetails]>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawApplications = frida_device_enumerate_applications_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                var applications: [ApplicationDetails] = []
                let n = frida_application_list_size(rawApplications)
                for i in 0..<n {
                    let application = ApplicationDetails(handle: frida_application_list_get(rawApplications, i))
                    applications.append(application)
                }
                g_object_unref(gpointer(rawApplications))

                op.resumeSuccess(applications)
            }, op.userData)

            g_object_unref(gpointer(options))
        }
    }

    public func enumerateProcesses(pids: [UInt]? = nil, scope: Scope? = nil) async throws -> [ProcessDetails] {
        return try await fridaAsync([ProcessDetails].self) { op in
            let options = frida_process_query_options_new()

            for pid in pids ?? [] {
                frida_process_query_options_select_pid(options, guint(pid))
            }

            if let scope {
                frida_process_query_options_set_scope(options, FridaScope(scope.rawValue))
            }

            frida_device_enumerate_processes(self.handle, options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<[ProcessDetails]>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawProcesses = frida_device_enumerate_processes_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                var processes: [ProcessDetails] = []
                let n = frida_process_list_size(rawProcesses)
                for i in 0..<n {
                    let process = ProcessDetails(handle: frida_process_list_get(rawProcesses, i))
                    processes.append(process)
                }
                g_object_unref(gpointer(rawProcesses))

                op.resumeSuccess(processes)
            }, op.userData)

            g_object_unref(gpointer(options))
        }
    }

    public func enableSpawnGating() async throws {
        return try await fridaAsync(Void.self) { op in
            frida_device_enable_spawn_gating(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_device_enable_spawn_gating_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func disableSpawnGating() async throws {
        return try await fridaAsync(Void.self) { op in
            frida_device_disable_spawn_gating(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_device_disable_spawn_gating_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func enumeratePendingSpawn() async throws -> [SpawnDetails] {
        return try await fridaAsync([SpawnDetails].self) { op in
            frida_device_enumerate_pending_spawn(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<[SpawnDetails]>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawSpawn = frida_device_enumerate_pending_spawn_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                var spawn: [SpawnDetails] = []
                let n = frida_spawn_list_size(rawSpawn)
                for i in 0..<n {
                    let details = SpawnDetails(handle: frida_spawn_list_get(rawSpawn, i))
                    spawn.append(details)
                }
                g_object_unref(gpointer(rawSpawn))

                op.resumeSuccess(spawn)
            }, op.userData)
        }
    }

    public func enumeratePendingChildren() async throws -> [ChildDetails] {
        return try await fridaAsync([ChildDetails].self) { op in
            frida_device_enumerate_pending_children(self.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<[ChildDetails]>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawChildren = frida_device_enumerate_pending_children_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                var children: [ChildDetails] = []
                let n = frida_child_list_size(rawChildren)
                for i in 0..<n {
                    let details = ChildDetails(handle: frida_child_list_get(rawChildren, i))
                    children.append(details)
                }
                g_object_unref(gpointer(rawChildren))

                op.resumeSuccess(children)
            }, op.userData)
        }
    }

    public func spawn(_ program: String, argv: [String]? = nil, envp: [String: String]? = nil, env: [String: String]? = nil,
                      cwd: String? = nil, stdio: Stdio? = nil) async throws -> UInt {
        return try await fridaAsync(UInt.self) { op in
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

            if let cwd {
                frida_spawn_options_set_cwd(options, cwd)
            }

            if let stdio {
                frida_spawn_options_set_stdio(options, FridaStdio(stdio.rawValue))
            }

            frida_device_spawn(self.handle, program, options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<UInt>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let pid = frida_device_spawn_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(UInt(pid))
            }, op.userData)

            g_object_unref(gpointer(options))
        }
    }

    public func input(_ pid: UInt, data: [UInt8]) async throws {
        return try await fridaAsync(Void.self) { op in
            let rawData = Marshal.bytesFromArray(data)

            frida_device_input(self.handle, guint(pid), rawData, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_device_input_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)

            g_bytes_unref(rawData)
        }
    }

    public func resume(_ pid: UInt) async throws {
        return try await fridaAsync(Void.self) { op in
            frida_device_resume(self.handle, guint(pid), op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_device_resume_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func kill(_ pid: UInt) async throws {
        return try await fridaAsync(Void.self) { op in
            frida_device_kill(self.handle, guint(pid), op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Void>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                frida_device_kill_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(())
            }, op.userData)
        }
    }

    public func attach(to pid: UInt, realm: Realm? = nil, persistTimeout: UInt? = nil) async throws -> Session {
        return try await fridaAsync(Session.self) { op in
            let options = frida_session_options_new()

            if let realm {
                frida_session_options_set_realm(options, FridaRealm(realm.rawValue))
            }

            if let persistTimeout {
                frida_session_options_set_persist_timeout(options, guint(persistTimeout))
            }

            frida_device_attach(self.handle, guint(pid), options, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<Session>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawSession = frida_device_attach_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                let session = Session(handle: rawSession!)
                op.resumeSuccess(session)
            }, op.userData)

            g_object_unref(gpointer(options))
        }
    }

    public func injectLibraryFile(into pid: UInt, path: String, entrypoint: String, data: String) async throws -> UInt {
        return try await fridaAsync(UInt.self) { op in
            frida_device_inject_library_file(self.handle, guint(pid), path, entrypoint, data, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<UInt>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawId = frida_device_inject_library_file_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(UInt(rawId))
            }, op.userData)
        }
    }

    public func injectLibraryBlob(into pid: UInt, blob: [UInt8], entrypoint: String, data: String) async throws -> UInt {
        return try await fridaAsync(UInt.self) { op in
            let rawBlob = Marshal.bytesFromArray(blob)

            frida_device_inject_library_blob(self.handle, guint(pid), rawBlob, entrypoint, data, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<UInt>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawId = frida_device_inject_library_blob_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(UInt(rawId))
            }, op.userData)

            g_bytes_unref(rawBlob)
        }
    }

    public func openChannel(_ address: String) async throws -> IOStream {
        return try await fridaAsync(IOStream.self) { op in
            frida_device_open_channel(self.handle, address, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<IOStream>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawStream = frida_device_open_channel_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                let stream = IOStream(handle: rawStream!)
                op.resumeSuccess(stream)
            }, op.userData)
        }
    }

    private let onSpawnAdded: SpawnAddedHandler = { _, rawSpawn, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawSpawn))
        let spawn = SpawnDetails(handle: rawSpawn)

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device(device, didAddSpawn: spawn)
            }
        }
    }

    private let onSpawnRemoved: SpawnRemovedHandler = { _, rawSpawn, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawSpawn))
        let spawn = SpawnDetails(handle: rawSpawn)

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device(device, didRemoveSpawn: spawn)
            }
        }
    }

    private let onChildAdded: ChildAddedHandler = { _, rawChild, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawChild))
        let child = ChildDetails(handle: rawChild)

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device(device, didAddChild: child)
            }
        }
    }

    private let onChildRemoved: ChildRemovedHandler = { _, rawChild, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawChild))
        let child = ChildDetails(handle: rawChild)

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device(device, didRemoveChild: child)
            }
        }
    }

    private let onProcessCrashed: ProcessCrashedHandler = { _, rawCrash, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        g_object_ref(gpointer(rawCrash))
        let crash = CrashDetails(handle: rawCrash)

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device(device, didObserveCrash: crash)
            }
        }
    }

    private let onOutput: OutputHandler = { _, pid, fd, rawData, rawDataSize, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        var data = [UInt8](repeating: 0, count: Int(rawDataSize))
        _ = data.withUnsafeMutableBytes { dst in
            memcpy(dst.baseAddress, rawData, Int(rawDataSize))
        }

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device(device, didOutput: data, toFileDescriptor: Int(fd), fromProcess: UInt(pid))
            }
        }
    }

    private let onUninjected: UninjectedHandler = { _, id, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.device(device, didUninject: UInt(id))
            }
        }
    }

    private let onLost: LostHandler = { _, userData in
        let connection = Unmanaged<SignalConnection<Device>>.fromOpaque(userData).takeUnretainedValue()

        if let device = connection.instance {
            Runtime.scheduleOnMainThread {
                device.delegate?.deviceLost(device)
            }
        }
    }

    private let releaseConnection: GClosureNotify = { data, _ in
        Unmanaged<SignalConnection<Device>>.fromOpaque(data!).release()
    }
}

@frozen
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

@frozen
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

@frozen
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
