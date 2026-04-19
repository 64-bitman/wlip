project(
  'wlip',
  'c',
  default_options: ['c_std=c11', 'warning_level=2', 'b_ndebug=if-release'],
)

add_project_arguments(
  ['-D_GNU_SOURCE'],
  language: 'c'
)

sources = []
includes = []

wl_dep = dependency('wayland-client')
json_dep = dependency('json-c')
sqlite_dep = dependency('sqlite3')

subdir('src')

wlip = executable(
  'wlip',
  'src/main.c',
  sources,
  include_directories: includes,
  dependencies: [wl_dep, json_dep, sqlite_dep],
  install: true
)
