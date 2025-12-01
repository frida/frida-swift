@frozen
public enum Error: Swift.Error, Codable {
    case serverNotRunning(String)
    case executableNotFound(String)
    case executableNotSupported(String)
    case processNotFound(String)
    case processNotResponding(String)
    case invalidArgument(String)
    case invalidOperation(String)
    case permissionDenied(String)
    case addressInUse(String)
    case timedOut(String)
    case notSupported(String)
    case protocolViolation(String)
    case transport(String)
    case rpcError(message: String, stackTrace: String?)

    public var description: String {
        switch self {
        case let .serverNotRunning(message),
             let .executableNotFound(message),
             let .executableNotSupported(message),
             let .processNotFound(message),
             let .processNotResponding(message),
             let .invalidArgument(message),
             let .invalidOperation(message),
             let .permissionDenied(message),
             let .addressInUse(message),
             let .timedOut(message),
             let .notSupported(message),
             let .protocolViolation(message),
             let .transport(message):
            return message

        case let .rpcError(message: message, stackTrace: stackTrace):
            if let stackTrace, !stackTrace.isEmpty {
                return "\(message)\n\n\(stackTrace)"
            }
            return message
        }
    }
}
