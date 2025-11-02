public final class RpcRequest {
    private var result: RpcInternalResult?
    private var promises: [(RpcInternalResult) -> Void] = []

    internal func received(result: RpcInternalResult) {
        self.result = result

        for promise in promises {
            promise(result)
        }

        promises.removeAll(keepingCapacity: false)
    }

    public func onResult<T>(as: T.Type,
                            callback: @escaping (RpcResult<T>) -> Void) {

        let promise = { (result: RpcInternalResult) in
            switch result {
            case let .success(untypedValue):
                guard let typedValue = untypedValue as? T else {
                    let error = Error.rpcError(message: "Failed to cast result \(String(describing: untypedValue)) to \(T.self)",
                        stackTrace: nil)
                    callback(.error(error))
                    return
                }
                callback(.success(typedValue))
            case let .error(error):
                callback(.error(error))
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
    case error(Swift.Error)
}
