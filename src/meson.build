sources += files('util.c', 'base64.c', 'log.c')
includes += include_directories('.')

daemon_sources += files('event.c', 'wayland_base.c', 'tomlc17.c', 'config_base.c')
gui_sources += files('tomlc17.c', 'config_base.c')

client_sources += files('ipc_client.c')

subdir('protocol')
subdir('daemon')
subdir('cli')
subdir('gtk')
