project(
  'wlip',
  'c',
  license: 'MIT',
  license_files: 'LICENSE',
  default_options: ['c_std=gnu11', 'warning_level=2'],
  meson_version: '>= 1.1.0'
)

sources = []
includes = []

libuv_dep = dependency('libuv')
sqlite_dep = dependency('sqlite3', version: '>=3.35.0')
wl_dep = dependency('wayland-client')

subdir('src')

version_h = vcs_tag(
  input: 'src/version.h.in',
  output: 'version.h',
  command: ['git', 'describe', '--tags', '--always', '--long'],
  fallback: meson.project_version(),
)

wlip = executable(
  'wlip',
  'src/main.c',
  sources,
  version_h,
  include_directories: includes,
  dependencies: [libuv_dep, sqlite_dep, wl_dep],
)

subdir('test')
