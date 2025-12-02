import Frida_Private

public final class PackageManager: @unchecked Sendable, CustomStringConvertible, Equatable, Hashable {
    public var events: Events {
        eventSource.makeStream()
    }

    public typealias Events = AsyncStream<Event>

    @frozen
    public enum Event {
        case installProgress(phase: PackageInstallPhase, fraction: Double, details: String?)
    }

    private let handle: OpaquePointer
    private let eventSource = AsyncEventSource<Event>()

    public init() {
        Runtime.ensureInitialized()

        self.handle = frida_package_manager_new()

        connectSignal(instance: self, handle: handle, signal: "install-progress", handler: onInstallProgress)
    }

    deinit {
        eventSource.finish()
        g_object_unref(gpointer(handle))
    }

    public var description: String {
        "Frida.PackageManager()"
    }

    public static func == (lhs: PackageManager, rhs: PackageManager) -> Bool {
        lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }

    public var registry: String {
        get {
            return String(cString: frida_package_manager_get_registry(handle))
        }
        set {
            frida_package_manager_set_registry(handle, newValue)
        }
    }

    public func search(query: String, options: PackageSearchOptions? = nil) async throws -> PackageSearchResult {
        return try await fridaAsync(PackageSearchResult.self) { op in
            frida_package_manager_search(self.handle, query, options?.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                    let op = InternalOp<PackageSearchResult>.takeRetained(from: userData!)

                    var rawError: UnsafeMutablePointer<GError>? = nil
                    let resultPtr = frida_package_manager_search_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                    if let rawError {
                        op.resumeFailure(Marshal.takeNativeError(rawError))
                        return
                    }

                    op.resumeSuccess(PackageSearchResult(handle: resultPtr!))
                }, op.userData)
        }
    }

    public func install(options: PackageInstallOptions? = nil) async throws -> PackageInstallResult {
        return try await fridaAsync(PackageInstallResult.self) { op in
            frida_package_manager_install(self.handle, options?.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                    let op = InternalOp<PackageInstallResult>.takeRetained(from: userData!)

                    var rawError: UnsafeMutablePointer<GError>? = nil
                    let resultPtr = frida_package_manager_install_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                    if let rawError {
                        op.resumeFailure(Marshal.takeNativeError(rawError))
                        return
                    }

                    op.resumeSuccess(PackageInstallResult(handle: resultPtr!))
                }, op.userData)
        }
    }

    private let onInstallProgress: @convention(c) (OpaquePointer, FridaPackageInstallPhase, gdouble, UnsafePointer<gchar>?, gpointer)
            -> Void = { _, nativePhase, fraction, rawDetails, userData in
        let connection = Unmanaged<SignalConnection<PackageManager>>.fromOpaque(userData).takeUnretainedValue()

        guard let manager = connection.instance else { return }

        let phase = PackageInstallPhase(rawValue: nativePhase.rawValue)!
        let details = rawDetails.map { String(cString: $0) }

        manager.publish(.installProgress(phase: phase, fraction: Double(fraction), details: details))
    }

    private func publish(_ event: Event) {
        eventSource.yield(event)
    }
}

@frozen
public enum PackageInstallPhase: UInt32, Codable, CustomStringConvertible {
    case initializing
    case preparingDependencies
    case resolvingPackage
    case fetchingResource
    case packageAlreadyInstalled
    case downloadingPackage
    case packageInstalled
    case resolvingAndInstallingAll
    case complete

    public var description: String {
        switch self {
        case .initializing:              return "initializing"
        case .preparingDependencies:     return "preparing-dependencies"
        case .resolvingPackage:          return "resolving-package"
        case .fetchingResource:          return "fetching-resource"
        case .packageAlreadyInstalled:   return "package-already-installed"
        case .downloadingPackage:        return "downloading-package"
        case .packageInstalled:          return "package-installed"
        case .resolvingAndInstallingAll: return "resolving-and-installing-all"
        case .complete:                  return "complete"
        }
    }
}

public final class Package: @unchecked Sendable, CustomStringConvertible, Equatable, Hashable {
    internal let handle: OpaquePointer

    internal init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var name: String {
        String(cString: frida_package_get_name(handle))
    }

    public var version: String {
        String(cString: frida_package_get_version(handle))
    }

    public var descriptionText: String? {
        guard let cstr = frida_package_get_description(handle) else { return nil }
        return String(cString: cstr)
    }

    public var url: String? {
        guard let cstr = frida_package_get_url(handle) else { return nil }
        return String(cString: cstr)
    }

    public var description: String {
        "\(name)@\(version)"
    }

    public static func == (lhs: Package, rhs: Package) -> Bool {
        lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }
}

@frozen
public enum PackageRole: UInt32, Codable, CustomStringConvertible {
    case runtime
    case development
    case optional
    case peer

    public var description: String {
        switch self {
        case .runtime:     return "runtime"
        case .development: return "development"
        case .optional:    return "optional"
        case .peer:        return "peer"
        }
    }
}

public final class PackageSearchOptions: @unchecked Sendable {
    internal let handle: OpaquePointer

    public init() {
        Runtime.ensureInitialized()

        self.handle = frida_package_search_options_new()
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var offset: UInt {
        get {
            UInt(frida_package_search_options_get_offset(handle))
        }
        set {
            frida_package_search_options_set_offset(handle, guint(newValue))
        }
    }

    public var limit: UInt {
        get {
            UInt(frida_package_search_options_get_limit(handle))
        }
        set {
            frida_package_search_options_set_limit(handle, guint(newValue))
        }
    }
}

public final class PackageSearchResult: @unchecked Sendable {
    public let packages: [Package]
    public let total: UInt

    internal init(handle: OpaquePointer) {
        self.total = UInt(frida_package_search_result_get_total(handle))
        self.packages = makePackages(from: frida_package_search_result_get_packages(handle))
        g_object_unref(gpointer(handle))
    }
}

public final class PackageInstallOptions: @unchecked Sendable {
    internal let handle: OpaquePointer

    private var _specs: [String] = []
    private var _omits: [PackageRole] = []

    public init() {
        Runtime.ensureInitialized()

        self.handle = frida_package_install_options_new()
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var projectRoot: String? {
        get {
            guard let cstr = frida_package_install_options_get_project_root(handle) else {
                return nil
            }
            return String(cString: cstr)
        }
        set {
            frida_package_install_options_set_project_root(handle, newValue)
        }
    }

    public var role: PackageRole {
        get {
            return PackageRole(rawValue: frida_package_install_options_get_role(handle).rawValue)!
        }
        set {
            frida_package_install_options_set_role(handle, FridaPackageRole(rawValue: newValue.rawValue))
        }
    }

    public var specs: [String] {
        get { _specs }
        set {
            _specs = newValue

            frida_package_install_options_clear_specs(handle)
            for spec in newValue {
                frida_package_install_options_add_spec(handle, spec)
            }
        }
    }

    public var omits: [PackageRole] {
        get { _omits }
        set {
            _omits = newValue

            frida_package_install_options_clear_omits(handle)
            for role in newValue {
                frida_package_install_options_add_omit(
                    handle,
                    FridaPackageRole(rawValue: role.rawValue)
                )
            }
        }
    }
}

public final class PackageInstallResult: @unchecked Sendable {
    public let packages: [Package]

    internal init(handle: OpaquePointer) {
        self.packages = makePackages(from: frida_package_install_result_get_packages(handle))
        g_object_unref(gpointer(handle))
    }
}

fileprivate func makePackages(from list: OpaquePointer) -> [Package] {
    let count = Int(frida_package_list_size(list))
    var result: [Package] = []
    result.reserveCapacity(count)

    for i in 0..<count {
        result.append(Package(handle: frida_package_list_get(list, gint(i))))
    }

    return result
}
