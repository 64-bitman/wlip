project(
  'wlip',
  'c',
  default_options: [
    'c_std=c11',
    'warning_level=2',
    'b_ndebug=if-release'
  ],
)

add_project_arguments(
  [
    '-D_GNU_SOURCE',
    '-Wcast-align',
    '-Winit-self',
    '-Wnull-dereference',
    '-Wno-float-equal',
    '-Winline',
  ],
  language: 'c'
)

if get_option('buildtype').startswith('debug')
  add_project_arguments(
    '-DDEBUG',
    '-ggdb3',
    language : 'c'
  )
endif

version_h = vcs_tag(
  input: 'src/version.h.in',
  output: 'version.h',
  command: ['git', 'describe', '--tags', '--always', '--long'],
  fallback: meson.project_version(),
)

subdir('src')
