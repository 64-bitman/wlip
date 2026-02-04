test_sources = []
test_includes = []

subdir('unity')

tests = ['array', 'hashtable', 'ringbuffer']

wlserver_dep = dependency('wayland-server')
compositor_lib = static_library(
  'compositor',
  'compositor.c',
  'compositor.h',
  comp_sources,
  util_sources,
  include_directories: [test_includes, includes],
  dependencies: wlserver_dep
)

foreach test : tests
  exe = executable(
    'test_' + test,
    'test_' + test + '.c',
    test_sources,
    util_sources,
    include_directories: [test_includes, includes],
    c_args : ['-DTESTING'],
  )

  test(
    test,
    exe,
    protocol: 'exitcode',
    suite: 'unit'
  )
endforeach

# wayland = executable(
#   'test_wayland',
#   'test_wayland.c',
#   util_sources,
#   wl_sources,
#   clip_sources,
#   test_sources,
#   dependencies: [wl_dep, sqlite_dep, lua_dep],
#   include_directories: [test_includes, includes],
#   link_with: compositor_lib
# )

# test(
#   'wayland',
#   wayland,
#   protocol: 'exitcode',
#   suite: 'integration'
# )
