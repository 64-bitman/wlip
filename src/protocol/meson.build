wayland_scanner = find_program('wayland-scanner', required: true, native: true)

if not wayland_scanner.found()
  subdir_done()
endif

protocols = ['ext-data-control-v1', 'wlr-data-control-unstable-v1']

foreach protocol : protocols
  name = protocol
  xml = name + '.xml'

  client_header = custom_target(
    name + ' client header',
    input: xml,
    output: name + '.h',
    command: [wayland_scanner, 'client-header', '@INPUT@', '@OUTPUT@']
  )

  server_header = custom_target(
    name + ' server header',
    input: xml,
    output: name + '_server.h',
    command: [wayland_scanner, 'server-header', '@INPUT@', '@OUTPUT@']
  )

  code = custom_target(
    name + ' code',
    input: xml,
    output: name + '.c',
    command: [wayland_scanner, 'private-code', '@INPUT@', '@OUTPUT@']
  )

  wl_sources += [client_header, code]
  comp_sources += [server_header, code]
endforeach
