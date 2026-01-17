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
    include_directories: [test_includes, includes],
  )

  test(
    test,
    exe,
    protocol: 'exitcode'
  )
endforeach
