#!/usr/bin/env bash

set -xeuo pipefail

if [[ $# < 2 ]]; then
    echo "Renames a kernel and its System.map to a unique value." >&2
    echo "Optionally: Generate ISF file." >&2
    echo "Usage: $0 <kernel> <system_map> [--symbols]" >&2
    exit 1
fi

kernel="$(pwd)/$1"
system_map="$(pwd)/$2"
kernelhash=$(md5sum $kernel | rg '([0-9a-f]+?) ' -r '$1' -o)

mv $kernel "$(dirname $kernel)/$kernelhash.elf" || true
mv $system_map "$(dirname $system_map)/$kernelhash.map" || true

kernel="/io/kernels/${kernelhash}.elf"
system_map="/io/kernels/${kernelhash}.map"
symbols="/io/symbols/${kernelhash}.isf.json"
d2j="/opt/vol/dwarf2json/dwarf2json"

if [[ $# = 3 ]]; then
    echo "Generating ISF file, this may take a while"
fi

docker run \
    --name "ISF_${kernelhash}" \
    --rm \
    -i \
    -v "$(pwd)/io:/io" \
    -w="/io" \
    bpfvol3:latest \
    /bin/bash -c "$d2j linux --elf $kernel --system-map $system_map | tee $symbols"

symbols="./io/symbols/${kernelhash}.isf.json"
./scripts/fix_symbols.sh ${symbols}
