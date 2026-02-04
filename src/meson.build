clip_sources += files('clipboard.c', 'database.c')
server_sources = files('event.c', 'server.c', 'server_api.c', 'json_util.c')
util_sources += files('alloc.c', 'array.c', 'hashtable.c', 'ringbuffer.c', 'util.c', 'sha256.c')
wl_sources += files('wayland.c')

includes += include_directories('.')

subdir('lua')
subdir('protocol')
