subdir('Frida_Private')

sources = [
  'ApplicationDetails.swift',
  'AsyncEventSource.swift',
  'AsyncOperation.swift',
  'Bus.swift',
  'ChildDetails.swift',
  'CrashDetails.swift',
  'Device.swift',
  'DeviceManager.swift',
  'DeviceListModel.swift',
  'Error.swift',
  'File.swift',
  'GType.swift',
  'IOStream.swift',
  'Icon+AppKit.swift',
  'Icon+CGImage.swift',
  'Icon+SwiftUI.swift',
  'Icon+UIKit.swift',
  'Icon.swift',
  'JSON.swift',
  'Marshal.swift',
  'PortalMembership.swift',
  'ProcessDetails.swift',
  'Relay.swift',
  'RpcFunction.swift',
  'Runtime.swift',
  'Script.swift',
  'Session.swift',
  'SignalConnection.swift',
  'SpawnDetails.swift',
  'TlsCertificate.swift',
  'UUID.swift',
]

extra_link_args = []
if host_os_family == 'darwin'
  extra_link_args += ['-Xlinker', '-exported_symbol', '-Xlinker', '_$*']
elif cc.get_argument_syntax() != 'msvc'
  extra_link_args += ['-Xlinker', '-export-symbols-regex', '-Xlinker', '^_\\$.+']
endif

frida_lib = shared_library('Frida', sources,
  include_directories: include_directories('.'),
  swift_args: [
    '-swift-version', '5',
    '-enable-library-evolution',
    '-emit-module-interface',
    '-framework', 'Foundation',
  ],
  link_args: extra_link_args,
  dependencies: frida_private_dep,
  install: host_os_family != 'darwin',
)

if host_os_family == 'darwin'
  custom_target('frida-framework',
    input: [
      frida_lib,
      'Frida.h',
      'Info.plist',
    ],
    output: 'Frida.framework',
    command: [
      python,
      files('generate-framework.py'),
      host_triplet,
      '@OUTPUT@',
      '@INPUT@',
    ],
    install: true,
    install_dir: get_option('prefix') / 'Frameworks',
  )
endif
