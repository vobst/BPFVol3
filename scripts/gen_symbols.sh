#!/usr/bin/env bash

set -euo pipefail

DOCKER_CMD="sudo -E docker"

if [[ $# -ne 2 ]]; then
    echo "Generate ISF file" >&2
    echo "Usage: $0 <kernel> <system_map>" >&2
    exit 1
fi

kernel_path="$1"
kernel_name="$(basename ${kernel_path})"
systemmap_path="$2"
kernelhash=$(sha256sum ${kernel_path} | rg '([0-9a-f]+?) ' -r '$1' -o | head -c 5 || true)
maphash=$(sha256sum ${systemmap_path} | rg '([0-9a-f]+?) ' -r '$1' -o | head -c 5 || true)

kernel="io/kernels/${kernel_name}-${kernelhash}.elf"
system_map="io/kernels/${kernel_name}-${kernelhash}-${maphash}.map"
symbols="io/symbols/${kernel_name}-${kernelhash}-${maphash}.btf2json.isf.json"

mv "${kernel_path}" "${kernel}"
mv "${systemmap_path}" "${system_map}"

btf2json \
    --btf "io/kernels/${kernel_name}-${kernelhash}.elf" \
    --map "io/kernels/${kernel_name}-${kernelhash}-${maphash}.map" |
    tee "$symbols"

./scripts/validate_schema.py \
    "$symbols" \
    "./volatility3/volatility3/schemas/schema-6.2.0.json"

kernel="/${kernel}"
system_map="/${system_map}"
symbols="/io/symbols/${kernel_name}-${kernelhash}-${maphash}.dwarf2json.isf.json"
d2j="/opt/vol/dwarf2json/dwarf2json"

echo "Generating ISF file, this may take a while"

$DOCKER_CMD run \
    --name "ISF_${kernel_name}_${kernelhash}" \
    --rm \
    -i \
    -v "$(pwd)/io:/io" \
    -w="/io" \
    bpfvol3:latest \
    /bin/bash -c "$d2j linux --elf $kernel --system-map $system_map | tee $symbols"

# uncomment if experience missing basic types
#symbols="./io/symbols/${kernelhash}.isf.json"
#./scripts/fix_symbols.sh ${symbols}
