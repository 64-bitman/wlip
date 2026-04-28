wayland_scanner = find_program('wayland-scanner', required: true, native: true)

if not wayland_scanner.found()
  subdir_done()
endif

daemon_protocols = ['ext-data-control-v1']
gui_protocols = ['wlr-layer-shell-unstable-v1', 'xdg-shell']
all_protocols = [daemon_protocols, gui_protocols]

foreach protocols : all_protocols
  foreach protocol : protocols
    name = protocol
    xml = name + '.xml'

    client_header = custom_target(
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

    if protocols == daemon_protocols
      daemon_sources += [client_header, code]
    else
      gui_sources += [client_header, code]
    endif
  endforeach
endforeach
