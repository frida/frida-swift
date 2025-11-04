# frida-swift

Swift bindings for [Frida](https://frida.re) — the dynamic instrumentation
toolkit.

`frida-swift` lets you use Frida from Swift or SwiftUI through fully
`async/await`-based APIs and structured concurrency instead of delegates.

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

  for a shared installation.
  You may first want to configure the prefix:

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
    @StateObject private var model = DeviceListModel(manager: DeviceManager())
    @State private var selectedDevice: Device?
    @State private var session: Session?

    var body: some View {
        NavigationStack {
            List(model.devices, id: \.id) { device in
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
                if model.devices.isEmpty {
                    ProgressView("Searching for devices…")
                }
            }
        }
    }
}
```

### Key points

- `DeviceListModel` wraps `DeviceManager` and updates reactively as devices are
  added or removed.
- The view stays in sync with live Frida device hot-plug events.
- You can call async APIs like `device.attach(to:)` directly from SwiftUI
  actions.

---

## 🚀 Example (Async / Test-style)

For non-SwiftUI contexts, use the async streams directly:

```swift
func testFullCycle() async throws {
    let manager = DeviceManager()

    for await devices in await manager.snapshots() {
        guard let local = devices.first(where: { $0.kind == .local }) else { continue }

        let session = try await local.attach(to: 12345)
        let script = try await session.createScript("""
            console.log("hello");
            send(1337);
        """)

        Task {
            for await event in script.events {
                switch event {
                case .message(let message, _):
                    print("Message:", message)
                case .destroyed:
                    print("Script destroyed")
                }
            }
        }

        try await script.load()
        break
    }
}
```

### Notes

- `DeviceManager` emits live device snapshots via `await manager.snapshots()`.
- Events are delivered through `AsyncStream`.
- All APIs support structured concurrency and `Task` cancellation.

---

## 🧠 Design Philosophy

`frida-swift` aims to be:

- **Swifty** — embracing `async/await`, actors, and `AsyncSequence` instead of
  callbacks.
- **Zero boilerplate** — no manual threading or delegate wiring.
- **Faithful to Frida** — same capabilities as the C APIs, expressed in
  idiomatic Swift.

API stability is not yet guaranteed — we’re still refining the concurrency model
before freezing the surface.

---

## ⚖️ License

`frida-swift` is distributed under the **wxWindows Library Licence, Version
3.1**.
See the accompanying [COPYING](./COPYING) file for full license text.
