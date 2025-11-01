# frida-swift

Swift bindings for [Frida](https://frida.re) — the dynamic instrumentation
toolkit.

`frida-swift` lets you use Frida from Swift or SwiftUI with fully
`async/await`-based APIs and reactive bindings.

---

## 🧩 Install

Build and install the framework locally:

```bash
make
```

Then either:

- Copy `build/Frida/Frida.framework` into your Xcode project, **or**
- Run:

  ```bash
  make install
  ```

  If you want a shared installation.
  In that case, you may first want to run:

  ```bash
  ./configure --prefix=/your/installation/prefix
  ```

---

## 🖥️ Example (SwiftUI)

Here’s a minimal SwiftUI view that lists connected devices and lets you tap to
attach:

```swift
import Frida
import SwiftUI

struct DevicesView: View {
    @StateObject private var manager = DeviceManager()
    @State private var selectedDevice: Device?
    @State private var session: Session?

    var body: some View {
        NavigationStack {
            List(manager.devices, id: \.id) { device in
                Button {
                    Task {
                        selectedDevice = device
                        session = try? await device.attach(to: 12345)
                    }
                } label: {
                    VStack(alignment: .leading) {
                        Text(device.name)
                            .font(.headline)
                        Text(device.kind.rawValue)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Frida Devices")
            .overlay {
                if manager.devices.isEmpty {
                    ProgressView("Searching for devices…")
                }
            }
            .alert(
                "Error",
                isPresented: Binding(
                    get: { manager.lastError != nil },
                    set: { _ in manager.lastError = nil }
                ),
                actions: { Button("OK", role: .cancel) {} },
                message: { Text(manager.lastError?.localizedDescription ?? "") }
            )
        }
    }
}
```

### Key points

- `DeviceManager` is a `@StateObject`, so the view updates automatically as
  devices are added or removed (e.g., USB or remote hotplug).
- `manager.devices` is always the current list.
- You can call async APIs like `device.attach(to:)` directly from button actions
  inside `Task { ... }` blocks.

---

## 🚀 Example (Async / Test-style)

For non-SwiftUI contexts (e.g. unit tests), you can use Frida’s APIs directly:

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

    let localDevice = try await manager.$devices
        .values
        .compactMap { devices in devices.first { $0.kind == .local } }
        .first(where: { _ in true })

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

### Notes

- `DeviceManager` automatically tracks device hotplug and emits changes via its
  `@Published` `devices` property.
- No delegate boilerplate: Frida signals are bridged directly into reactive
  Swift properties.
- The `AsyncSequence` approach above is production-safe and avoids polling.

---

## 🧠 Design Philosophy

`frida-swift` aims to be:

- **Swifty** — embracing `async/await`, `@MainActor`, and SwiftUI’s reactive
  model.
- **Zero boilerplate** — no manual threading, no delegate wiring unless truly
  necessary.
- **Faithful to Frida** — what you can do in Frida’s C or JS APIs, you can do
  here, just idiomatically.

API stability is not yet guaranteed — the focus is on making it the best
possible Swift binding before freezing the surface.

---

## ⚖️ License

`frida-swift` is distributed under the **wxWindows Library Licence, Version
3.1**.  See the accompanying [COPYING](./COPYING) file for full license text.
