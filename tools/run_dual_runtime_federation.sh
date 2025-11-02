#!/bin/sh
set -euo pipefail

builddir="${1:-build}"
exe="${builddir}/cep_tests"

if [ ! -x "${exe}" ]; then
    echo "error: ${exe} not found. Build the test suite first (ninja -C ${builddir} cep_tests)." >&2
    exit 1
fi

run_target="/CEP/runtime/dual_isolation"
args="--no-fork --single ${run_target}"

"${exe}" ${args} &
pid1=$!

"${exe}" ${args} &
pid2=$!

wait ${pid1}
wait ${pid2}
