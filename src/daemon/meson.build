sources = files(
  'wlip.c',
  'config.c',
  'wayland.c',
  'database.c',
  'sha256.c',
  'ipc.c',
  'util.c',
  'base64.c',
  'log.c',
  'wayland_base.c',
  'tomlc17.c',
  'event.c',
  'config_base.c'
)
includes = include_directories('.')

wl_dep = dependency('wayland-client')
json_dep = dependency('json-c')
sqlite_dep = dependency('sqlite3')

subdir('protocol')

wlip = executable(
  'wlip',
  'main.c',
  sources,
  version_h,
  include_directories: includes,
  dependencies: [wl_dep, json_dep, sqlite_dep],
  install: true
)
