test_sources = []
test_includes = []

subdir('unity')

tests = ['array', 'hashtable', 'ringbuffer']

foreach test : tests
  exe = executable(
    'test_' + test,
    'test_' + test + '.c',
    test_sources,
    sources,
    dependencies: [sqlite_dep, wl_dep, jsonc_dep, lua_dep],
    include_directories: [test_includes, includes],
    c_args : ['-DTESTING']
  )

  test(
    test,
    exe,
    protocol: 'exitcode'
  )
endforeach
