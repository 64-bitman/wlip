test_sources = []
test_includes = []

subdir('unity')

tests = [['array', []], ['hashtable', []], ['loop', ['-DTEST_LOOP_RAW']]]

foreach test : tests
  exe = executable(
    'test_' + test[0],
    'test_' + test[0] + '.c',
    test_sources,
    sources,
    dependencies: [sqlite_dep, wl_dep, jansson_dep],
    include_directories: [test_includes, includes],
    link_with: link_with,
    c_args: test[1]
  )

  test(
    test[0],
    exe,
    protocol: 'exitcode'
  )
endforeach
