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
        let expectation = self.expectation(description: "Got list of devices")

        let manager = DeviceManager()
        var devices: [Device] = []
        manager.enumerateDevices { result in
            devices = try! result()
            expectation.fulfill()
        }

        self.waitForExpectations(timeout: 5.0, handler: nil)

        print("Got devices: \(devices)")
        for device in devices {
            print("\(device.name) Icon: \(String(describing: device.icon))")
            device.querySystemParameters { result in
                do {
                    let parameters = try result()
                    print("Device \(device.name) parameters: \(parameters)")
                } catch let error {
                    print("Failed to query system parameters for \(device.name): \(error)")
                }
            }
        }

        manager.close()
        XCTAssert(devices.count > 0)
    }

    func testAddRemoteDevice() {
        let manager = DeviceManager()

        let expectation = self.expectation(description: "Got processes from remote server")
        manager.addRemoteDevice(address: "::1", certificate: "/Users/oleavr/src/cert.pem", token: "letmein", keepaliveInterval: 5) { result in
            let device = try! result()
            device.enumerateProcesses { result in
                do {
                    let processes = try result()
                    print("Got processes from remote server: \(processes)")
                    expectation.fulfill()
                } catch let error {
                    XCTFail("Error getting processes from remote server: \(error)")
                }
            }
        }
        self.waitForExpectations(timeout: 5.0, handler: nil)
    }

    func testGetFrontmostApplication() {
        let expectation = self.expectation(description: "Got frontmost application")

        let manager = DeviceManager()
        var application: ApplicationDetails?
        manager.enumerateDevices { result in
            let devices = try! result()
            guard let usbDevice = devices.filter({ $0.kind == Device.Kind.usb }).first else {
                print("No USB devices for test \(#function).")
                expectation.fulfill()
                return
            }
            usbDevice.getFrontmostApplication(scope: .full) { result in
                do {
                    application = try result()
                } catch let error {
                    XCTFail("Error getting frontmost application: \(error)")
                }
                expectation.fulfill()
            }
        }

        self.waitForExpectations(timeout: 5.0, handler: nil)
        XCTAssertNotNil(application)
        if let application = application {
            print("Got application: \(application.debugDescription)")
        }
    }

    func testEnumerateApplications() {
        let expectation = self.expectation(description: "Got list of applications")

        let manager = DeviceManager()
        var applications: [ApplicationDetails] = []
        manager.enumerateDevices { result in
            let devices = try! result()

            guard let usbDevice = devices.filter({ $0.kind == Device.Kind.usb }).first else {
                print("No USB devices for test \(#function).")
                expectation.fulfill()
                return
            }

            usbDevice.enumerateApplications(scope: .full) { result in
                do {
                    applications = try result()
                } catch let error {
                    XCTFail("Error enumerating applications: \(error)")
                }
                expectation.fulfill()
            }
        }

        self.waitForExpectations(timeout: 5.0, handler: nil)

        print("Got \(applications.count) applications")
        for application in applications {
            print(application)
        }

        XCTAssert(applications.count > 0)
    }

    func testEnumerateProcesses() {
        let expectation = self.expectation(description: "Got list of processes")

        let manager = DeviceManager()
        var processes: [ProcessDetails] = []
        manager.enumerateDevices { result in
            let devices = try! result()
            let device = devices.filter { $0.kind == Device.Kind.usb }.first!
            device.enumerateProcesses(pids: [38886, 1], scope: .full) { result in
                processes = try! result()
                expectation.fulfill()
            }
        }

        self.waitForExpectations(timeout: 5.0, handler: nil)

        print("Got \(processes.count) processes")
        for process in processes {
            print(process)
        }

        XCTAssert(processes.count > 0)
    }

    func xxxtestDetached() {
        let pid: UInt = 63626

        let expectation = self.expectation(description: "Got detached from session")

        class TestDelegate : SessionDelegate {
            let expectation: XCTestExpectation
            var reason: SessionDetachReason?

            init(expectation: XCTestExpectation) {
                self.expectation = expectation
            }

            func session(_ session: Session, didDetach reason: SessionDetachReason, crash: CrashDetails?) {
                self.reason = reason
                expectation.fulfill()
            }
        }
        let delegate = TestDelegate(expectation: expectation)

        let manager = DeviceManager()
        var session: Session? = nil
        manager.enumerateDevices { result in
            let devices = try! result()
            let localDevice = devices.filter { $0.kind == Device.Kind.local }.first!
            localDevice.attach(to: pid) { result in
                session = try! result()
                session!.delegate = delegate
            }
        }

        self.waitForExpectations(timeout: 60.0, handler: nil)
        print("Got detached from \(session!), reason: \(delegate.reason!)")
    }

    func xxxtestFullCycle() {
        let pid: UInt = 20854

        let expectation = self.expectation(description: "Got message from script")

        class TestDelegate : ScriptDelegate {
            let expectation: XCTestExpectation
            var messages: [Any] = []

            init(expectation: XCTestExpectation) {
                self.expectation = expectation
            }

            func scriptDestroyed(_: Script) {
                print("destroyed")
            }

            func script(_: Script, didReceiveMessage message: Any, withData data: Data?) {
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
            let localDevice = devices.filter { $0.kind == Device.Kind.local }.first!
            localDevice.attach(to: pid) { result in
                let session = try! result()
                session.createScript("console.log(\"hello\"); send(1337);", name: "test") { result in
                    let s = try! result()
                    s.delegate = delegate
                    s.load() { result in
                        _ = try! result()
                        print("Script loaded")
                    }
                    script = s
                }
            }
        }

        self.waitForExpectations(timeout: 5.0, handler: nil)
        print("Done with script \(script.debugDescription), messages: \(delegate.messages)")
    }
}
