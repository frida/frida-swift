import Frida
import XCTest

final class FridaTests: XCTestCase {
    func testDeviceManagerSmokeTest() async throws {
        let manager = DeviceManager()
        for await devices in await manager.snapshots() {
            XCTAssertFalse(devices.isEmpty, "Expected at least the local device")
            break
        }
        try await manager.close()
    }
}
