import Frida_Private

public final class Compiler: @unchecked Sendable, CustomStringConvertible, Equatable, Hashable {
    public var events: Events {
        eventSource.makeStream()
    }

    public typealias Events = AsyncStream<Event>

    @frozen
    public enum Event {
        case starting
        case diagnostics(Any)
        case output(bundle: String)
        case finished
    }

    private let handle: OpaquePointer
    private let eventSource = AsyncEventSource<Event>()

    public init() {
        Runtime.ensureInitialized()

        self.handle = frida_compiler_new(nil)

        connectSignal(instance: self, handle: handle, signal: "starting", handler: onStarting)
        connectSignal(instance: self, handle: handle, signal: "finished", handler: onFinished)
        connectSignal(instance: self, handle: handle, signal: "output", handler: onOutput)
        connectSignal(instance: self, handle: handle, signal: "diagnostics", handler: onDiagnostics)
    }

    deinit {
        eventSource.finish()
        g_object_unref(gpointer(handle))
    }

    public var description: String {
        "Frida.Compiler()"
    }

    public static func == (lhs: Compiler, rhs: Compiler) -> Bool {
        lhs.handle == rhs.handle
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(UInt(bitPattern: handle))
    }

    public func build(entrypoint: String, options: BuildOptions? = nil) async throws -> String {
        return try await fridaAsync(String.self) { op in
            frida_compiler_build(self.handle, entrypoint, options?.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                    let op = InternalOp<String>.takeRetained(from: userData!)

                    var rawError: UnsafeMutablePointer<GError>? = nil
                    let bundleCString = frida_compiler_build_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                    if let rawError {
                        op.resumeFailure(Marshal.takeNativeError(rawError))
                        return
                    }

                    let bundle = String(cString: bundleCString!)
                    g_free(bundleCString)

                    op.resumeSuccess(bundle)
                }, op.userData)
        }
    }

    public func watch(entrypoint: String, options: WatchOptions? = nil) async throws {
        return try await fridaAsync(Void.self) { op in
            frida_compiler_watch(self.handle, entrypoint, options?.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                    let op = InternalOp<Void>.takeRetained(from: userData!)

                    var rawError: UnsafeMutablePointer<GError>? = nil
                    frida_compiler_watch_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                    if let rawError {
                        op.resumeFailure(Marshal.takeNativeError(rawError))
                        return
                    }

                    op.resumeSuccess(())
                }, op.userData)
        }
    }

    private let onStarting: @convention(c) (OpaquePointer, gpointer) -> Void = { _, userData in
        let connection = Unmanaged<SignalConnection<Compiler>>.fromOpaque(userData).takeUnretainedValue()

        guard let compiler = connection.instance else { return }

        compiler.publish(.starting)
    }

    private let onFinished: @convention(c) (OpaquePointer, gpointer) -> Void = { _, userData in
        let connection = Unmanaged<SignalConnection<Compiler>>.fromOpaque(userData).takeUnretainedValue()

        guard let compiler = connection.instance else { return }

        compiler.publish(.finished)
    }

    private let onOutput: @convention(c) (OpaquePointer, UnsafePointer<gchar>, gpointer) -> Void = { _, rawBundle, userData in
        let connection = Unmanaged<SignalConnection<Compiler>>.fromOpaque(userData).takeUnretainedValue()

        guard let compiler = connection.instance else { return }

        let bundle = String(cString: rawBundle)
        compiler.publish(.output(bundle: bundle))
    }

    private let onDiagnostics: @convention(c) (OpaquePointer, OpaquePointer?, gpointer) -> Void = { _, rawVariant, userData in
        let connection = Unmanaged<SignalConnection<Compiler>>.fromOpaque(userData).takeUnretainedValue()

        guard
            let compiler = connection.instance,
            let rawVariant
        else {
            return
        }

        compiler.publish(.diagnostics(Marshal.valueFromVariant(rawVariant)))
    }

    private func publish(_ event: Event) {
        eventSource.yield(event)
    }
}

public final class BuildOptions: CompilerOptions, @unchecked Sendable {
    public init() {
        super.init(handle: frida_build_options_new()!)
    }
}

public final class WatchOptions: CompilerOptions, @unchecked Sendable {
    public init() {
        super.init(handle: frida_watch_options_new()!)
    }
}

public class CompilerOptions: @unchecked Sendable {
    internal let handle: OpaquePointer

    internal init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        g_object_unref(gpointer(handle))
    }

    public var projectRoot: String? {
        get {
            guard let cstr = frida_compiler_options_get_project_root(handle) else { return nil }
            return String(cString: cstr)
        }
        set {
            frida_compiler_options_set_project_root(handle, newValue)
        }
    }

    public var outputFormat: OutputFormat {
        get {
            return OutputFormat(rawValue: frida_compiler_options_get_output_format(handle).rawValue)!
        }
        set {
            frida_compiler_options_set_output_format(handle, FridaOutputFormat(rawValue: newValue.rawValue))
        }
    }

    public var bundleFormat: BundleFormat {
        get {
            return BundleFormat(rawValue: frida_compiler_options_get_bundle_format(handle).rawValue)!
        }
        set {
            frida_compiler_options_set_bundle_format(handle, FridaBundleFormat(rawValue: newValue.rawValue))
        }
    }

    public var typeCheck: TypeCheckMode {
        get {
            return TypeCheckMode(rawValue: frida_compiler_options_get_type_check(handle).rawValue)!
        }
        set {
            frida_compiler_options_set_type_check(handle, FridaTypeCheckMode(rawValue: newValue.rawValue))
        }
    }

    public var sourceMaps: SourceMaps {
        get {
            return SourceMaps(rawValue: frida_compiler_options_get_source_maps(handle).rawValue)!
        }
        set {
            frida_compiler_options_set_source_maps(handle, FridaSourceMaps(rawValue: newValue.rawValue))
        }
    }

    public var compression: JsCompression {
        get {
            return JsCompression(rawValue: frida_compiler_options_get_compression(handle).rawValue)!
        }
        set {
            frida_compiler_options_set_compression(handle, FridaJsCompression(rawValue: newValue.rawValue))
        }
    }

    public var platform: JsPlatform {
        get {
            return JsPlatform(rawValue: frida_compiler_options_get_platform(handle).rawValue)!
        }
        set {
            frida_compiler_options_set_platform(handle, FridaJsPlatform(rawValue: newValue.rawValue))
        }
    }

    public var externals: [String] {
        get {
            final class Box {
                var items: [String] = []
            }

            let box = Box()
            let userData = Unmanaged.passRetained(box).toOpaque()

            frida_compiler_options_enumerate_externals(handle, { data, userData in
                    let box = Unmanaged<Box>.fromOpaque(userData!) .takeUnretainedValue()

                    let cstr = data!.assumingMemoryBound(to: CChar.self)
                    box.items.append(String(cString: cstr))
                }, userData)

            Unmanaged<Box>.fromOpaque(userData).release()

            return box.items
        }
        set {
            frida_compiler_options_clear_externals(handle)
            for ext in newValue {
                frida_compiler_options_add_external(handle, ext)
            }
        }
    }
}

@frozen
public enum OutputFormat: UInt32, Codable, CustomStringConvertible {
    case unescaped
    case hexBytes
    case cString

    public var description: String {
        switch self {
        case .unescaped: return "unescaped"
        case .hexBytes:  return "hex-bytes"
        case .cString:   return "c-string"
        }
    }
}

@frozen
public enum BundleFormat: UInt32, Codable, CustomStringConvertible {
    case esm
    case iife

    public var description: String {
        switch self {
        case .esm:  return "esm"
        case .iife: return "iife"
        }
    }
}

@frozen
public enum TypeCheckMode: UInt32, Codable, CustomStringConvertible {
    case full
    case none

    public var description: String {
        switch self {
        case .full: return "full"
        case .none: return "none"
        }
    }
}

@frozen
public enum SourceMaps: UInt32, Codable, CustomStringConvertible {
    case included
    case omitted

    public var description: String {
        switch self {
        case .included: return "included"
        case .omitted:  return "omitted"
        }
    }
}

@frozen
public enum JsCompression: UInt32, Codable, CustomStringConvertible {
    case none
    case terser

    public var description: String {
        switch self {
        case .none:   return "none"
        case .terser: return "terser"
        }
    }
}

@frozen
public enum JsPlatform: UInt32, Codable, CustomStringConvertible {
    case gum
    case browser
    case neutral

    public var description: String {
        switch self {
        case .gum:      return "gum"
        case .browser:  return "browser"
        case .neutral:  return "neutral"
        }
    }
}
