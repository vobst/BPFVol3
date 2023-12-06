#!/usr/bin/env bash

set -xeuo pipefail

if [[ $# -ne 2 ]]; then
    echo "Generate ISF file" >&2
    echo "Usage: $0 <kernel> <system_map>" >&2
    exit 1
fi

kernel_path="$1"
kernel_name="$(basename ${kernel_path})"
systemmap_path="$2"
kernelhash=$(md5sum ${kernel_path} | rg '([0-9a-f]+?) ' -r '$1' -o | head -c 5 || true)

mv ${kernel_path} "io/kernels/${kernel_name}-${kernelhash}.elf"
mv ${systemmap_path} "io/kernels/${kernel_name}-${kernelhash}.map"

kernel="/io/kernels/${kernel_name}-${kernelhash}.elf"
system_map="/io/kernels/${kernel_name}-${kernelhash}.map"
symbols="/io/symbols/${kernel_name}-${kernelhash}.isf.json"
d2j="/opt/vol/dwarf2json/dwarf2json"

echo "Generating ISF file, this may take a while"

docker run \
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
