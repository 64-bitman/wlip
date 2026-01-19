project(
  'wlip',
  'c',
  license: 'MIT',
  license_files: 'LICENSE',
  default_options: ['c_std=c11', 'warning_level=2', 'b_ndebug=if-release'],
  meson_version: '>= 1.1.0'
)

add_project_arguments(
  ['-D_GNU_SOURCE'],
  language: 'c'
)

sources = []
includes = []
link_with = []

sqlite_dep = dependency('sqlite3', version: '>=3.35.0')
wl_dep = dependency('wayland-client')
jansson_dep = dependency('jansson', version: '>=2.0.0')
lua_dep = dependency('lua', version: '>=5.4')

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
  dependencies: [sqlite_dep, wl_dep, jansson_dep, lua_dep],
  link_with: link_with
)

subdir('test')
