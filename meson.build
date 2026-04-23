project(
  'wlip',
  'c',
  default_options: ['c_std=c11', 'warning_level=2', 'b_ndebug=if-release'],
)

add_project_arguments(
  ['-D_GNU_SOURCE'],
  language: 'c'
)

daemon_sources = []
daemon_includes = []

cli_sources = []
cli_includes = []

sources = []
includes = []

wl_dep = dependency('wayland-client')
json_dep = dependency('json-c')
sqlite_dep = dependency('sqlite3')
gtkls_dep = dependency('gtk4-layer-shell-0')
glib_dep = dependency('gtk4')
gtk4_dep = dependency('glib-2.0')

subdir('src')

wlip = executable(
  'wlip',
  'src/daemon/main.c',
  daemon_sources,
  sources,
  include_directories: [includes, daemon_includes],
  dependencies: [wl_dep, json_dep, sqlite_dep],
  install: true
)

wlip_cli = executable(
  'wlipctl',
  'src/cli/main.c',
  cli_sources,
  sources,
  include_directories: [includes, cli_includes],
  dependencies: [json_dep],
  install: true
)
