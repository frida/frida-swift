@dynamicCallable
public struct RpcFunction {
    unowned let script: Script
    let functionName: String

    init(script: Script, functionName: String) {
        self.script = script
        self.functionName = functionName
    }

    public func dynamicallyCall(withArguments args: [Any]) async throws -> Any? {
        return try await script.rpcCall(functionName: functionName, args: args)
    }

    public func callAsFunction<T>(_ args: Any...) async throws -> T {
        let anyValue = try await script.rpcCall(functionName: functionName, args: args)
        if let typed = anyValue as? T {
            return typed
        }

        throw Error.rpcError(
            message: "Failed to cast result \(String(describing: anyValue)) to \(T.self)",
            stackTrace: nil
        )
    }
}
