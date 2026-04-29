gnome = import('gnome')

gui_sources += gnome.compile_resources(
    'wlipgtk', 'wlipgtk.gresource.xml',
)

gui_sources += files('gui.c', 'config.c')
gui_includes += include_directories('.')
