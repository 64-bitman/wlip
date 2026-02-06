test_sources = []
test_includes = []

subdir('unity')

tests = ['array', 'hashtable', 'ringbuffer']

wlserver_dep = dependency('wayland-server')
wlip_compositor = executable(
  'wlip_compositor',
  'compositor.c',
  comp_sources,
  dependencies: [wlserver_dep, jsonc_dep],
  c_args : ['-DWLR_USE_UNSTABLE'],
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
