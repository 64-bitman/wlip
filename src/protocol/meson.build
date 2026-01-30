wayland_scanner = find_program('wayland-scanner', required: true, native: true)

if not wayland_scanner.found()
  subdir_done()
endif

protocols = ['ext-data-control-v1', 'wlr-data-control-unstable-v1']

foreach protocol : protocols
  name = protocol
  xml = name + '.xml'

  header = custom_target(
    name + ' client header',
    input: xml,
    output: name + '.h',
    command: [wayland_scanner, 'client-header', '@INPUT@', '@OUTPUT@']
  )

  code = custom_target(
    name + ' code',
    input: xml,
    output: name + '.c',
    command: [wayland_scanner, 'private-code', '@INPUT@', '@OUTPUT@']
  )

  sources += [header, code]
endforeach
