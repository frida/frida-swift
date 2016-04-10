class SignalConnection<T: AnyObject> {
    weak var instance: T?

    init(instance: T) {
        self.instance = instance
    }
}
