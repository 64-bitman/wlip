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

subdir('src')

version_h = vcs_tag(
  input: 'src/version.h.in',
  output: 'version.h',
  command: ['git', 'describe', '--tags', '--always', '--long'],
  fallback: meson.project_version(),
)

wlip = executable(
  'wlip',
  'src/daemon/main.c',
  daemon_sources,
  sources,
  version_h,
  include_directories: [includes, daemon_includes],
  dependencies: [wl_dep, json_dep, sqlite_dep],
  install: true
)

wlip_cli = executable(
  'wlipctl',
  'src/cli/main.c',
  cli_sources,
  sources,
  version_h,
  include_directories: [includes, cli_includes],
  dependencies: [json_dep],
  install: true
)
