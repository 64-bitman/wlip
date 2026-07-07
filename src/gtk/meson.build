sources = files('wlipdaemon.c')
includes = include_directories('.')

glib_dep = dependency('glib-2.0')
glib_json_dep = dependency('json-glib-1.0')
gtk4_dep = dependency('gtk4')
gtkls_dep = dependency('gtk4-layer-shell-0')
glycin_dep = dependency('glycin-2')
glycingtk4_dep = dependency('glycin-gtk4-2')

wlipgtk = executable(
  'wlipgtk',
  'main.c',
  sources,
  version_h,
  include_directories: includes,
  dependencies: [
    glib_dep,
    glib_json_dep,
    gtk4_dep,
    gtkls_dep,
    glycin_dep,
    glycingtk4_dep,
  ],
  install: true
)
