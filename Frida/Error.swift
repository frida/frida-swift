import Foundation

public enum Error: ErrorType {
    case ServerNotRunning(String)
    case ExecutableNotFound(String)
    case ExecutableNotSupported(String)
    case ProcessNotFound(String)
    case ProcessNotResponding(String)
    case InvalidArgument(String)
    case InvalidOperation(String)
    case PermissionDenied(String)
    case AddressInUse(String)
    case TimedOut(String)
    case NotSupported(String)
    case ProtocolViolation(String)
    case Transport(String)
}