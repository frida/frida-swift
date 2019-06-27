import Foundation

@dynamicCallable
public struct RpcFunction {
    unowned let script: Script
    let functionName: String

    init(script: Script, functionName: String) {
        self.script = script
        self.functionName = functionName
    }

    func dynamicallyCall(withArguments args: [Any]) throws -> RpcRequest {
        return try script.rpcPost(functionName: functionName,
                                  requestId: script.nextRequestId, values: args)
    }
}
