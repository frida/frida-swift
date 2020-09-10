# frida-swift

Swift bindings for [Frida](https://frida.re).

## Install

- Build Frida for your Mac, e.g. `make core-macos-thin`
- Generate a devkit:

    ./releng/devkit.py -t frida-core macos-x86_64 ./frida-swift/CFrida/

- Open and build with Xcode.

## Example

```swift
func testFullCycle() {
    let pid: UInt = 20854

    let expectation = self.expectation(description: "Got message from script")

    class TestDelegate : ScriptDelegate {
        let expectation: XCTestExpectation
        var messages = [Any]()

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
        localDevice.attach(pid) { result in
            let session = try! result()
            session.createScript("test", source: "console.log(\"hello\"); send(1337);") { result in
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
    print("Done with script \(script), messages: \(delegate.messages)")
}
```
