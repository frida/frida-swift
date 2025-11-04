import Combine

@MainActor
public final class DeviceListModel: ObservableObject {
    @Published public private(set) var devices: [Device] = []
    @Published public private(set) var discoveryState: DiscoveryState = .discovering

    @frozen
    public enum DiscoveryState: Equatable {
        case discovering
        case ready
    }

    public let manager: DeviceManager

    public init(manager: DeviceManager) {
        self.manager = manager

        Task {
            self.devices = await manager.currentDevices()
            self.discoveryState = .ready

            for await snapshot in await manager.snapshots() {
                self.devices = snapshot
            }
        }
    }
}
