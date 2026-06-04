gnome = import('gnome')

gui_sources += gnome.compile_resources(
    'wlipgtk-resources', 'resources.gresource.xml',
)

gui_sources += files(
  'clipboard-entry.c',
  'clipboard-list.c',
  'entry-box.c',
  'ipc-handle.c',
  'entry-content.c'
)
gui_includes += include_directories('.')
