project('CEP', 'c',
  version: '0.1.0',
  license: 'MPL-2.0',
  default_options: [
    'c_std=c11',
    'warning_level=2',
    'default_library=static',
  ]
)

cc = meson.get_compiler('c')
fs = import('fs')
python_mod = import('python')

# Includes
inc = include_directories('src/l0_kernel', 'src/test', 'src/enzymes')

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
  '-DCEP_RV_DISABLED=1',
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
zip_opt = get_option('zip')
zip_dep = dependency('libzip', required: zip_opt.enabled(), method: 'pkg-config', allow_fallback: true)

l0_srcs = files(
  'src/l0_kernel/cep_cell.c',
  'src/l0_kernel/cep_cell_stream.c',
  'src/l0_kernel/cep_cell_system.c',
  'src/l0_kernel/cep_l0.c',
  'src/l0_kernel/cep_identifier.c',
  'src/l0_kernel/cep_cei.c',
  'src/l0_kernel/cep_mailbox.c',
  'src/l0_kernel/cep_ops.c',
  'src/l0_kernel/cep_organ.c',
  'src/l0_kernel/cep_ep.c',
  'src/l0_kernel/cep_executor.c',
  'src/enzymes/cep_l0_organs.c',
  'src/enzymes/cep_cell_operations.c',
  'src/l0_kernel/stream/cep_stream_stdio.c',
  'src/l0_kernel/stream/cep_stream_effects.c',
  'src/l0_kernel/cep_enzyme_bindings.c',
  'src/l0_kernel/cep_heartbeat_queue.c',
  'src/l0_kernel/cep_enzyme.c',
  'src/l0_kernel/cep_heartbeat.c',
  'src/l0_kernel/cep_namepool.c',
  'src/l0_kernel/cep_serialization.c',
)

lib_dependencies = []
host_sys = host_machine.system()

if zip_dep.found()
  l0_srcs += files('src/l0_kernel/stream/cep_stream_zip.c')
  add_project_arguments('-DCEP_HAS_LIBZIP=1', language: 'c')
  lib_dependencies += [zip_dep]
endif

exe_cargs = []
if host_sys == 'windows'
  # Workaround: define only for test builds on Windows due to munit atomics bug.
  exe_cargs += ['-D__STDC_NO_ATOMICS__']
endif

# Build the core library (static by default; both if requested)
both_libs = get_option('both_libs')
executor_backend = get_option('executor_backend')
if (host_sys == 'emscripten' or host_sys.startswith('wasm')) and executor_backend == 'threaded'
  warning('Threaded executor backend unavailable on ' + host_sys + '; falling back to stub backend')
  executor_backend = 'stub'
endif

if executor_backend == 'threaded'
  add_project_arguments('-DCEP_EXECUTOR_BACKEND_THREADED=1', language: 'c')
else
  add_project_arguments('-DCEP_EXECUTOR_BACKEND_STUB=1', language: 'c')
endif
lib_kw = {
  'include_directories': inc,
  'install': true,
}
if both_libs
  lib_kw += {'both_libraries': true}
endif
if lib_dependencies.length() > 0
  lib_kw += {'dependencies': lib_dependencies}
endif
cep_lib = library('cep', l0_srcs,
  kwargs: lib_kw,
)

if get_option('tests').enabled()
  test_srcs = files(
    'src/test/munit.c',
    'src/test/test.c',
    'src/test/watchdog.c',
    'src/test/l0_kernel/test_cell.c',
    'src/test/l0_kernel/test_cell_mutations.c',
    'src/test/l0_kernel/test_cell_immutable.c',
    'src/test/l0_kernel/test_traverse.c',
    'src/test/l0_kernel/test_traverse_all.c',
    'src/test/l0_kernel/test_domain_tag_naming.c',
    'src/test/l0_kernel/test_identifier.c',
    'src/test/l0_kernel/test_ops.c',
      'src/test/l0_kernel/test_enzyme.c',
    'src/test/l0_kernel/test_heartbeat.c',
    'src/test/l0_kernel/test_mailbox.c',
    'src/test/l0_kernel/test_cei.c',
    'src/test/l0_kernel/test_stream.c',
    'src/test/l0_kernel/test_executor.c',
    'src/test/l0_kernel/test_serialization.c',
    'src/test/l0_kernel/test_locking.c',
    'src/test/l0_kernel/test_cells_randomized.c',
    'src/test/l0_kernel/test_locking_randomized.c',
    'src/test/l0_kernel/test_scheduler_randomized.c',
    'src/test/l0_kernel/test_organ_validators.c',
    'src/test/l0_kernel/test_organ_dossiers.c',
    'src/test/l0_kernel/test_serialization_randomized.c',
    'src/test/l0_kernel/test_streams_randomized.c',
    'src/test/l0_kernel/test_prr.c',
    'src/test/poc/l0_integration_poc.c',
    )
  test_dependencies = []
  if zip_dep.found()
    test_srcs += files('src/test/l0_kernel/test_stream_zip.c')
    test_dependencies += [zip_dep]
  endif
  exe = executable('cep_tests', test_srcs,
    c_args: exe_cargs,
    include_directories: inc,
    link_with: cep_lib,
    dependencies: test_dependencies,
    install: false,
  )
  test('cep_unit_tests', exe,
    args: ['--no-fork', '--param', 'timeout', '120'],
    timeout: 180,
  )

  test('integration_poc', exe,
    args: ['--no-fork', '--single', '/CEP/integration_poc/l0/integration'],
    timeout: 240,
    suite: ['integration_poc'],
  )

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

code_map_opt = get_option('code_map')
docs_html_opt = get_option('docs_html')
python_needed = code_map_opt or docs_html_opt
python3 = python_mod.find_installation('python3', required: python_needed)
if python3.found()
  code_map_script = files('tools/generate_code_map.py')
  code_map_outputs = [
    'code_map_ctags.json',
    'code_map_cscope_callees.tsv',
    'code_map_cscope_callers.tsv',
  ]
  code_map_command = [
    python3,
    code_map_script,
    '--source-root', meson.project_source_root(),
    '--ctags-output', '@OUTPUT0@',
    '--callees-output', '@OUTPUT1@',
    '--callers-output', '@OUTPUT2@',
    '--cscope-database', join_paths(meson.current_build_dir(), 'code_map_cscope.out'),
    '--cscope-listing', join_paths(meson.current_build_dir(), 'code_map_cscope.files'),
    '--include', 'src',
  ]
  custom_target('code_map',
    output: code_map_outputs,
    command: code_map_command,
    depend_files: [code_map_script],
    build_by_default: false,
    build_always_stale: code_map_opt,
  )
elif code_map_opt
  warning('code_map option requested but python3 was not found; skipping code map target.')
endif

doxygen = find_program('doxygen', required: docs_html_opt)
dot = find_program('dot', required: docs_html_opt)

docs_missing = []
if not python3.found()
  docs_missing += ['python3']
endif
if not doxygen.found()
  docs_missing += ['doxygen']
endif
if not dot.found()
  docs_missing += ['graphviz (dot)']
endif

docs_ready = docs_missing.length() == 0

if docs_html_opt and not docs_ready
  error('docs_html option requires the following tools: ' + ', '.join(docs_missing) + '.')
endif

if docs_ready
  dot_path = fs.parent(dot.full_path())
  doc_output_dir = join_paths(meson.current_build_dir(), 'docs')
  main_page = ''
  if fs.exists('docs/CEP.md')
    main_page = join_paths(meson.project_source_root(), 'docs/CEP.md')
  elif fs.exists('docs/README.md')
    main_page = join_paths(meson.project_source_root(), 'docs/README.md')
  elif fs.exists('docs/BUILD.md')
    main_page = join_paths(meson.project_source_root(), 'docs/BUILD.md')
  endif

  doc_version = meson.project_version()
  git_tag_script = join_paths(meson.project_source_root(), 'tools/git_tag_version.py')
  if python3.found() and fs.exists(git_tag_script)
    tag_cmd = run_command(python3, git_tag_script, check: false)
    if tag_cmd.returncode() == 0
      tag_output = tag_cmd.stdout().strip()
      if tag_output != ''
        doc_version = tag_output
      endif
    endif
  endif

  doxy_config = configuration_data()
  doxy_config.set('PROJECT_NAME', meson.project_name())
  doxy_config.set('PROJECT_VERSION', doc_version)
  doxy_config.set('OUTPUT_DIRECTORY', doc_output_dir)
  doxy_config.set('SOURCE_ROOT', meson.project_source_root())
  doxy_config.set('STRIP_FROM_PATH', meson.project_source_root())
  doxy_config.set('DOT_PATH', dot_path)
  doxy_config.set('MAIN_PAGE', main_page)

  doxyfile = configure_file(
    input: 'docs/Doxyfile.in',
    output: 'Doxyfile',
    configuration: doxy_config,
  )

  doxygen_runner = files('tools/run_doxygen.py')[0]
  git_tag_file = files('tools/git_tag_version.py')[0]
  fix_toc_script = files('tools/fix_doxygen_toc.py')[0]
  custom_target('docs_html',
    input: [doxyfile],
    output: 'docs_html.stamp',
    command: [
      python3,
      doxygen_runner,
      '--doxygen', doxygen.full_path(),
      '--config', '@INPUT0@',
      '--stamp', '@OUTPUT0@',
      '--post-process', fix_toc_script,
      '--html-root', join_paths(doc_output_dir, 'html'),
    ],
    depend_files: [doxygen_runner, git_tag_file, fix_toc_script],
    build_by_default: false,
    build_always_stale: docs_html_opt,
  )
else
  docs_message = 'HTML documentation requires python3, doxygen, and graphviz (dot); missing: ' + ', '.join(docs_missing)
  fallback_cmd = []
  if python3.found()
    fallback_cmd = [
      python3,
      '-c',
      'import sys; sys.stderr.write("' + docs_message.replace('"', '\\"') + '\n"); sys.exit(1)',
    ]
  elif host_sys == 'windows'
    fallback_cmd = ['cmd', '/C', 'echo ' + docs_message.replace('"', '""') + ' & exit 1']
  else
    fallback_cmd = ['sh', '-c', 'echo "' + docs_message.replace('"', '\\"') + '" >&2; exit 1']
  endif
  run_target('docs_html',
    command: fallback_cmd,
  )
endif
