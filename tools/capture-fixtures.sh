#!/usr/bin/env bash
set -euo pipefail

# Capture deterministic logs for key kernel behaviours so future refactors
# have a quick way to compare agenda ordering while TODOs cover the new ingest/scheduler work.

script_dir=$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "${script_dir}/.." && pwd)
build_dir="${repo_root}/build"
binary="${build_dir}/cep_tests.exe"

if [[ ! -x "${binary}" ]]; then
    echo "Capture failed: ${binary} is missing or not executable." >&2
    echo "Build the project first (e.g. meson compile -C build)." >&2
    exit 1
fi

fixtures_dir="${build_dir}/fixtures"
mkdir -p "${fixtures_dir}"

seed="0x13579bdf"
full_log="${fixtures_dir}/cep_tests_full.log"

echo ">> Running cep_tests.exe with seed ${seed}"
set +e
"${binary}" --seed "${seed}" --log-visible debug --show-stderr > "${full_log}" 2>&1
status=$?
set -e
if (( status != 0 )); then
    echo "Fixture capture completed with test failures (exit ${status}). See ${full_log}." >&2
fi

declare -a tests=(
    "/CEP/heartbeat"
)

for test in "${tests[@]}"; do
    slug="${test//\//_}"
    slug="${slug#_}"
    log_path="${fixtures_dir}/${slug}.log"

    awk -v start="${test}" '
        BEGIN { capture = 0; }
        /^\/CEP\// {
            if (index($0, start) == 1) {
                capture = 1;
                print;
                next;
            }
            capture = 0;
        }
        capture { print; }
    ' "${full_log}" > "${log_path}"
done

echo
echo "Captured fixtures:"
for log in "${fixtures_dir}"/*.log; do
    printf '  %s\n' "${log}"
done
