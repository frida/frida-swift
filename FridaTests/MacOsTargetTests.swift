import XCTest
@testable import Frida

fileprivate enum TestScriptMessage {
    case regular(type: String, payload: String)
    case other(message: Any, data: Data?)
}

fileprivate class TestScriptDelegate: NSObject, ScriptDelegate {
    var onMessage: ((TestScriptMessage) -> Void)?
    
    @objc func script(_ script: Script, didReceiveMessage message: Any, withData data: Data?) {
        guard let dict = message as? [String: String] else {
            onMessage?(.other(message: message, data: data))
            return
        }
        
        let typeMaybe = dict["type"]
        let payloadMaybe = dict["payload"]
        
        guard let type = typeMaybe, let payload = payloadMaybe else {
            print("Couldn't get type and payload")
            return
        }
        
        onMessage?(.regular(type: type, payload: payload))
    }
}

class MacOsTargetTests: XCTestCase {
    lazy var manager = DeviceManager()
    var localDevice: Device!
    var pid: UInt!
    var session: Session!
    var script: Script!
    fileprivate lazy var scriptDelegate: TestScriptDelegate = TestScriptDelegate()
    
    private func getProductsConfigurationDirectory() -> URL {
        let bundlePath = Bundle(for: MacOsTargetTests.self).bundlePath
        let url = URL(fileURLWithPath: bundlePath)
        return url.deletingLastPathComponent()
    }
    
    private func getSourceRoot() -> URL {
        let fileManager = FileManager.default
        var url = URL(fileURLWithPath: #file)
        while fileManager.fileExists(atPath: url.appendingPathComponent(".git").path) == false {
            url = url.deletingLastPathComponent()
            
            if url.pathComponents.count == 0 {
                url = URL(fileURLWithPath: #file).deletingLastPathComponent().deletingLastPathComponent()
                break
            }
        }
        
        return url
    }
    
    private func spawnSessionWith(script scriptContents: String) {
        let localDeviceExpectation = expectation(description: "Found local device.")
        var localDeviceMaybe: Device?
        manager.enumerateDevices { result in
            let devices = try! result()
            let localDevice = devices.filter { $0.kind == Device.Kind.local }.first!
            localDeviceMaybe = localDevice
            localDeviceExpectation.fulfill()
        }
        waitForExpectations(timeout: 2, handler: nil)
        XCTAssertNotNil(localDeviceMaybe)
        guard localDeviceMaybe != nil else { return }
        localDevice = localDeviceMaybe
        
        let binary = getProductsConfigurationDirectory().appendingPathComponent("TestTarget")
        let spawnExpectation = expectation(description: "Spawned binary.")
        var pidMaybe: UInt?
        localDevice.spawn(binary.path) { result in
            do {
                pidMaybe = try result()
            } catch let error {
                print("Couldn't launch, error: \(error)")
            }
            
            spawnExpectation.fulfill()
        }
        waitForExpectations(timeout: 2, handler: nil)
        XCTAssertNotNil(pidMaybe)
        guard pidMaybe != nil else { return }
        pid = pidMaybe
        
        let attachExpectation = expectation(description: "Attached to binary.")
        var sessionMaybe: Session?
        localDevice.attach(pid) { (result) in
            sessionMaybe = try? result()
            attachExpectation.fulfill()
        }
        waitForExpectations(timeout: 2, handler: nil)
        XCTAssertNotNil(sessionMaybe)
        guard sessionMaybe != nil else { return }
        session = sessionMaybe
        
        let createScriptExpectation = expectation(description: "Created script.")
        var scriptMaybe: Script?
        session.createScript(scriptContents) { (result) in
            scriptMaybe = try! result()
            createScriptExpectation.fulfill()
        }
        waitForExpectations(timeout: 2, handler: nil)
        XCTAssertNotNil(scriptMaybe)
        guard scriptMaybe != nil else { return }
        script = scriptMaybe
        script.delegate = scriptDelegate
    }
    
    override func tearDown() {
        manager.close()
    }
    
    func testReceiveMessage() {
        spawnSessionWith(script: #"console.log("done")"#)
        let messageExpectation = expectation(description: "Received message")
        
        scriptDelegate.onMessage = { message in
            if case let.regular(_, payload) = message, payload == "done" {
                messageExpectation.fulfill()
            }
        }
        
        script.load()
        localDevice.resume(pid)
        waitForExpectations(timeout: 2.0, handler: nil)
    }
    
    func testRpcCall() throws {
        let scriptContents = """
        rpc.exports = {
            add: function (a, b) {
                return a + b;
            }
        };
        """
        spawnSessionWith(script: scriptContents)
        script.load()
        
        let resultExpectation = expectation(description: "Received RPC result.")
        let add = script.exports.add
        
        try add(5, 3).onResult(as: Int.self) { result in
            switch result {
            case let .success(value):
                XCTAssertEqual(value, 5 + 3, "RPC Function called successfully.")
            case let .error(error):
                XCTFail(error.localizedDescription)
            }
            resultExpectation.fulfill()
        }
        
        waitForExpectations(timeout: 2.0, handler: nil)
        session.detach()
    }
}
