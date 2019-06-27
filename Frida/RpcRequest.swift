import Foundation

public class RpcRequest {
    private var result: RpcInternalResult?
    private var promises = [(RpcInternalResult) -> Void]()

    internal func received(result: RpcInternalResult) {
        self.result = result

        for promise in promises {
            promise(result)
        }

        promises.removeAll(keepingCapacity: false)
    }

    public func onResult<T>(as: T.Type,
                            callback: @escaping (RpcResult<T>) -> Void) throws {

        let promise = { (result: RpcInternalResult) in
            switch result {
            case let .success(untypedValue):
                guard let typedValue = untypedValue as? T else {
                    callback(.error(Error.rpcError("Failed to cast \(String(describing: untypedValue)) to \(T.self)")))
                    return
                }
                callback(.success(typedValue))
            case let .error(error):
                callback(.error(Error.rpcError(error)))
            }
        }

        if let result = result {
            promise(result)
        } else {
            promises.append(promise)
        }
    }
}

public enum RpcResult<T> {
    case success(T)
    case error(Swift.Error)
}

internal enum RpcInternalResult {
    case success(value: Any?)
    case error(error: String)
}
