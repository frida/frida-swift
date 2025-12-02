subdir('Frida_Private')

sources = [
  'ApplicationDetails.swift',
  'AsyncEventSource.swift',
  'AsyncOperation.swift',
  'AuthenticationService.swift',
  'Bus.swift',
  'ChildDetails.swift',
  'Compiler.swift',
  'CrashDetails.swift',
  'CustomAuthenticationService.swift',
  'Device.swift',
  'DeviceListModel.swift',
  'DeviceManager.swift',
  'EndpointParameters.swift',
  'Error.swift',
  'Error+Foundation.swift',
  'Icon+AppKit.swift',
  'Icon+CGImage.swift',
  'Icon+SwiftUI.swift',
  'Icon+UIKit.swift',
  'Icon.swift',
  'JSValue.swift',
  'Marshal.swift',
  'PortalMembership.swift',
  'PortalService.swift',
  'ProcessDetails.swift',
  'Relay.swift',
  'RpcFunction.swift',
  'Runtime.swift',
  'Script.swift',
  'Session.swift',
  'SignalConnection.swift',
  'SpawnDetails.swift',
]

subdir('GLib')
sources += glib_sources

subdir('JSONGLib')
sources += json_glib_sources

extra_link_args = []
extra_link_depends = []
if host_os_family == 'darwin'
  extra_link_args += ['-Xlinker', '-exported_symbol', '-Xlinker', '_$*']
elif cc.get_argument_syntax() != 'msvc'
  symscript = 'Frida.version'
  extra_link_args += ['-Xlinker', '--version-script', '-Xlinker', meson.current_source_dir() / symscript]
  extra_link_depends += symscript
endif

frida_incdirs = include_directories('.')

frida_lib = shared_library('Frida', sources,
  include_directories: frida_incdirs,
  swift_args: [
    '-swift-version', '5',
    '-enable-library-evolution',
    '-emit-module-interface',
  ],
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  dependencies: frida_private_dep,
  install: host_os_family != 'darwin',
)

frida_dep = declare_dependency(
  include_directories: frida_incdirs,
  link_with: frida_lib,
)

meson.override_dependency('frida-swift', frida_dep)

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
