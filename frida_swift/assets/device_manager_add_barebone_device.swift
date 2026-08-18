    @discardableResult
    public func addBareboneDevice(name: String, config: BareboneConfig) async throws -> Device {
        let deviceHandle = try await fridaAsync(OpaquePointer.self) { op in
            frida_device_manager_add_barebone_device(self.handle, name, config.handle, op.cancellable, { sourcePtr, asyncResultPtr, userData in
                let op = InternalOp<OpaquePointer>.takeRetained(from: userData!)

                var rawError: UnsafeMutablePointer<GError>? = nil
                let rawDeviceHandle = frida_device_manager_add_barebone_device_finish(OpaquePointer(sourcePtr), asyncResultPtr, &rawError)

                if let rawError {
                    op.resumeFailure(Marshal.takeNativeError(rawError))
                    return
                }

                op.resumeSuccess(rawDeviceHandle!)
            }, op.userData)
        }

        return await store.deviceForHandle(deviceHandle)
    }
