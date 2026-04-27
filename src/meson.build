sources += files('util.c', 'base64.c')
includes += include_directories('.')

daemon_sources += files('event.c')
gui_sources += files('event.c')

client_sources += files('ipc_client.c')

subdir('daemon')
subdir('cli')
subdir('gui')
