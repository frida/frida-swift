import CFrida

class AsyncOperation<CompletionHandler> {
    let completionHandler: CompletionHandler

    init(_ completionHandler: CompletionHandler) {
        self.completionHandler = completionHandler
    }
}