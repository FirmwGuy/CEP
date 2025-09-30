# CEP Build Options

The Meson build exposes the following configuration switches (see `meson_options.txt`).

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `asan` | boolean | `false` | Enable Address/Undefined sanitizers. |
| `code_map` | boolean | `false` | Generate ctags+cscope mapping artifacts. |
| `docs_html` | boolean | `false` | Build HTML documentation using Doxygen and Graphviz. |
| `tests` | feature | `enabled` | Build the unit-test suite (`enabled`, `disabled`, `auto`). |
| `server` | feature | `disabled` | Build the standalone CEP server binary. |
| `both_libs` | boolean | `false` | Build both static and shared variants of libcep. |
| `zip` | feature | `auto` | Enable the libzip-backed stream adapter. |

## Usage examples

```bash
meson setup build -Dtests=enabled -Dasan=true
meson compile -C build
meson test -C build
```

Set any option during the initial `meson setup` (or via `meson configure` on an existing build directory).
