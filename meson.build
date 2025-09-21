project('CEP', 'c',
  version: '0.1.0',
  default_options: [
    'c_std=c11',
    'warning_level=2',
    'default_library=static',
  ]
)

cc = meson.get_compiler('c')
fs = import('fs')

# Includes
inc = include_directories('src/l0_kernel', 'src/test')

# Global compile args to mirror Makefile
common_args = []
if cc.has_argument('-Wall')
  common_args += ['-Wall']
endif
if cc.has_argument('-g')
  common_args += ['-g']
endif
if cc.has_argument('-fplan9-extensions')
  common_args += ['-fplan9-extensions']
endif

add_project_arguments(common_args + [
  '-D_GNU_SOURCE',
], language: 'c')

# Optionally enable sanitizers (best with Clang on MinGW-UCRT)
asan_opt = get_option('asan')
asan_args = []
if asan_opt and cc.has_argument('-fsanitize=address')
  asan_args += ['-fsanitize=address']
  if cc.has_argument('-fsanitize=undefined')
    asan_args += ['-fsanitize=undefined']
  endif
  if cc.has_argument('-fno-omit-frame-pointer')
    asan_args += ['-fno-omit-frame-pointer']
  endif
  # Keep optimization low for sanitizer builds
  if cc.has_argument('-O1')
    asan_args += ['-O1']
  endif
  add_project_arguments(asan_args, language: 'c')
  add_project_link_arguments(asan_args, language: 'c')
endif

# Core library sources (heartbeat/enzymes are stubs for now but compiled in)
l0_srcs = files(
  'src/l0_kernel/cep_cell.c',
  'src/l0_kernel/cep_enzyme.c',
  'src/l0_kernel/cep_heartbeat.c',
)

exe_cargs = []
host_sys = host_machine.system()
if host_sys == 'windows'
  # Workaround: define only for test builds on Windows due to munit atomics bug.
  exe_cargs += ['-D__STDC_NO_ATOMICS__']
endif

# Build the core library (static by default; both if requested)
both_libs = get_option('both_libs')
lib_kw = {
  'include_directories': inc,
  'install': true,
}
if both_libs
  lib_kw += {'both_libraries': true}
endif
cep_lib = library('cep', l0_srcs,
  kwargs: lib_kw,
)

if get_option('tests').enabled()
  test_srcs = files(
    'src/test/munit.c',
    'src/test/test.c',
    'src/test/test_cell.c',
    'src/test/test_traverse.c',
    'src/test/test_wordacron.c',
    'src/test/test_enzyme.c',
  )
  exe = executable('cep_tests', test_srcs,
    c_args: exe_cargs,
    include_directories: inc,
    link_with: cep_lib,
    install: false,
  )
  test('cep_unit_tests', exe)
endif

# CEP server executable (optional; build only if enabled and sources exist)
if get_option('server').enabled()
  server_main = 'src/server/main.c'
  # If the file does not exist, skip with a warning.
  if not fs.exists(server_main)
    warning('Server enabled but no sources found at ' + server_main + '. Skipping server build.')
  else
    cep_server = executable('cep_server', files(server_main),
      include_directories: inc,
      link_with: cep_lib,
      install: true,
    )
  endif
endif
