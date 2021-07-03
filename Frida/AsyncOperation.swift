import CFrida

class AsyncOperation<CompletionHandler> {
    let completionHandler: CompletionHandler
    let userData: gpointer!

    init(_ completionHandler: CompletionHandler, userData: gpointer! = nil) {
        self.completionHandler = completionHandler
        self.userData = userData
    }
}
