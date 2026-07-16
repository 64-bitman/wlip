sources = files(
  'main.c',
  'wayland.c',
  'buffer.c',
  'surface.c'
)
includes = include_directories('.')

xkb_dep = dependency('xkbcommon')
wl_cursor_dep = dependency('wayland-cursor')
cairo_dep = dependency('cairo')
pango_dep = dependency('pangocairo')

wlippicker = executable(
  'wlippicker',
  sources,
  sources,
  client_sources,
  common_sources,
  picker_proto_sources,
  version_h,
  include_directories: [includes, client_includes, common_includes],
  dependencies: [wl_dep, json_dep, xkb_dep, wl_cursor_dep, cairo_dep, pango_dep],
  install: true
)
