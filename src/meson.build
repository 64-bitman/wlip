common_sources = files(
  'util.c',
  'base64.c',
  'log.c',
  'wayland_base.c',
  'tomlc17.c',
  'event.c',
  'config_base.c'
)
common_includes = include_directories('.')

wl_dep = dependency('wayland-client')
json_dep = dependency('json-c')

subdir('protocol')
subdir('daemon')
subdir('client')
