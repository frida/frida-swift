# frida-swift

Swift bindings for [Frida](https://frida.re).

## Install

- Run:

    make

- Copy `build/Frida/Frida.framework` into your project, or run `make install`
  if you need a shared installation. In the latter case you may want to first
  run `./configure` with a suitable `--prefix`.

## Example

```swift
func testFullCycle() async throws {
    let pid: UInt = 20854

    class TestDelegate: ScriptDelegate {
        var messages: [Any] = []
        var continuation: CheckedContinuation<Void, Never>?

        func scriptDestroyed(_: Script) {
            print("destroyed")
        }

        func script(_: Script, didReceiveMessage message: Any, withData data: Data?) {
            print("didReceiveMessage")
            messages.append(message)
            if messages.count == 2 {
                continuation?.resume()
                continuation = nil
            }
        }
    }

    let delegate = TestDelegate()
    let manager = DeviceManager()

    let devices = try await manager.devices
    let localDevice = devices.first { $0.kind == .local }!

    let session = try await localDevice.attach(to: pid)

    let script = try await session.createScript("""
        console.log("hello");
        send(1337);
        """)
    script.delegate = delegate
    try await script.load()
    print("Script loaded")

    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
        delegate.continuation = continuation
    }

    print("Done with script \(script), messages: \(delegate.messages)")
}
```
