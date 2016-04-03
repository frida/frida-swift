import XCTest
@testable import Frida

class FridaTests: XCTestCase {

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testEnumerateDevices() {
        let expectation = self.expectationWithDescription("Got list of devices")

        let manager = DeviceManager()
        var devices = [Device]()
        manager.enumerateDevices { result in
            devices = try! result()
            expectation.fulfill()
        }
        manager.close()

        self.waitForExpectationsWithTimeout(5.0, handler: nil)
        // print("Got devices: \(devices)")
        assert(devices.count > 0)
    }

    func testGetFrontmostApplication() {
        let expectation = self.expectationWithDescription("Got frontmost application")

        let manager = DeviceManager()
        var application: ApplicationDetails?
        manager.enumerateDevices { result in
            let devices = try! result()
            let usbDevice = devices.filter { $0.kind == Device.Kind.Tether }.first!
            usbDevice.getFrontmostApplication() { result in
                application = try! result()
                expectation.fulfill()
            }
        }

        self.waitForExpectationsWithTimeout(5.0, handler: nil)
        print("Got application: \(application)")
    }

    func testEnumerateApplications() {
        let expectation = self.expectationWithDescription("Got list of applications")

        let manager = DeviceManager()
        var applications = [ApplicationDetails]()
        manager.enumerateDevices { result in
            let devices = try! result()
            let usbDevice = devices.filter { $0.kind == Device.Kind.Tether }.first!
            usbDevice.enumerateApplications() { result in
                applications = try! result()
                expectation.fulfill()
            }
        }

        self.waitForExpectationsWithTimeout(5.0, handler: nil)
        // print("Got applications: \(applications)")
        assert(applications.count > 0)
    }

    func testEnumerateProcesses() {
        let expectation = self.expectationWithDescription("Got list of processes")

        let manager = DeviceManager()
        var processes = [ProcessDetails]()
        manager.enumerateDevices { result in
            let devices = try! result()
            let localDevice = devices.filter { $0.kind == Device.Kind.Local }.first!
            localDevice.enumerateProcesses() { result in
                processes = try! result()
                expectation.fulfill()
            }
        }

        self.waitForExpectationsWithTimeout(5.0, handler: nil)
        // print("Got processes: \(processes)")
        assert(processes.count > 0)
    }

    func XXXtestFullCycle() {
        let pid: UInt = 20854

        let expectation = self.expectationWithDescription("Got message from script")

        class TestDelegate : ScriptDelegate {
            let expectation: XCTestExpectation
            var messages = [AnyObject]()

            init(expectation: XCTestExpectation) {
                self.expectation = expectation
            }

            func scriptDestroyed(_: Script) {
                print("destroyed")
            }

            func script(_: Script, didReceiveMessage message: AnyObject, withData data: NSData) {
                print("didReceiveMessage")
                messages.append(message)
                if messages.count == 2 {
                    expectation.fulfill()
                }
            }
        }
        let delegate = TestDelegate(expectation: expectation)

        let manager = DeviceManager()
        var script: Script? = nil
        manager.enumerateDevices { result in
            let devices = try! result()
            let localDevice = devices.filter { $0.kind == Device.Kind.Local }.first!
            localDevice.attach(pid) { result in
                let session = try! result()
                session.createScript("test", source: "console.log(\"hello\"); send(1337);") { result in
                    let s = try! result()
                    s.delegate = delegate
                    s.load() { result in
                        try! result()
                        print("Script loaded")
                    }
                    script = s
                }
            }
        }

        self.waitForExpectationsWithTimeout(5.0, handler: nil)
        print("Done with script \(script), messages: \(delegate.messages)")
    }
}
