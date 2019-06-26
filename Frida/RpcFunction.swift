import Foundation

@dynamicCallable
public struct RpcFunction {
    unowned var script: Script?
    let functionName: String
    
    init(script: Script?, functionName: String) {
        self.script = script
        self.functionName = functionName
    }
    
    func dynamicallyCall(withArguments args: [Any]) throws -> RpcRequest {
        guard let script = self.script else {
            throw Error.rpcError("Script has gone away.")
        }
        
        return try script.rpcPost(functionName: functionName,
                                  requestId: script.nextRequestId, values: args)
    }
}
