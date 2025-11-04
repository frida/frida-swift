public actor AsyncEventSource<Event> {
    public typealias Stream = AsyncStream<Event>

    private var nextID: Int = 0
    private var continuations: [Int: Stream.Continuation] = [:]
    private var isFinished = false

    public init() {}

    public nonisolated func makeStream() -> Stream {
        Stream { continuation in
            Task { await self.addSubscriber(continuation) }
        }
    }

    public nonisolated func yield(_ event: Event) {
        Task { await self.emit(event) }
    }

    public nonisolated func finish() {
        Task { await self.finishAll() }
    }

    private func addSubscriber(_ continuation: Stream.Continuation) {
        if isFinished {
            continuation.finish()
            return
        }

        let id = nextID
        nextID &+= 1
        continuations[id] = continuation

        continuation.onTermination = { [weak self] _ in
            guard let self else { return }
            Task { await self.removeSubscriber(id) }
        }
    }

    private func removeSubscriber(_ id: Int) {
        continuations.removeValue(forKey: id)
    }

    private func emit(_ event: Event) {
        if isFinished {
            return
        }

        let current = Array(continuations.values)
        for c in current {
            c.yield(event)
        }
    }

    private func finishAll() {
        if isFinished {
            return
        }

        isFinished = true
        let current = Array(continuations.values)
        continuations.removeAll()

        for c in current {
            c.finish()
        }
    }
}
