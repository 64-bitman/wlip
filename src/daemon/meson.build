sources = files(
  'main.c',
  'wlip.c',
  'config.c',
  'wayland.c',
  'database.c',
  'sha256.c',
  'ipc.c'
)
includes = include_directories('.')

sqlite_dep = dependency('sqlite3')

wlip = executable(
  'wlip',
  sources,
  common_sources,
  daemon_proto_sources,
  version_h,
  include_directories: [includes, common_includes],
  dependencies: [wl_dep, json_dep, sqlite_dep],
  install: true
)
