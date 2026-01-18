test_sources = []
test_includes = []

subdir('unity')

tests = ['array', 'hashtable']

foreach test : tests
  exe = executable(
    'test_' + test,
    'test_' + test + '.c',
    test_sources,
    sources,
    dependencies: [libuv_dep, sqlite_dep, wl_dep],
    include_directories: [test_includes, includes],
    link_with: link_with
  )

  test(
    test,
    exe,
    protocol: 'exitcode'
  )
endforeach
