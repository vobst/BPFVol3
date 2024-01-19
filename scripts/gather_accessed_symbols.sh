#!/usr/bin/env bash

set -u

if [[ $# -eq 0 ]]; then
    echo "Generates a list of all symbols whose type is accesed when running"
    echo "all available V3 plugins on a memory image."
    echo "This script is intended to be run inside the analysis container:"
    echo './vol.sh --run <name of script> [arg]*'
    echo ""
    echo "Usage: $0 <path/to/image>"
    exit 1
fi

IMAGE=$1
OFILE="/io/output/used_symbol_types_$IMAGE"

rm -rf $OFILE*

for plugin in $(vol --help | grep -Eo '(linux\.\S+)'); do
    if [[ $plugin == "linux.check_syscall.Check_syscall" ]] || [[ $plugin == "linux.bpf_lsm.BpfLsm" ]]; then
        # Those plugins iterate over (all) symbols and call `get_symbol` which
        # accesses the type for caching purposes. However, they do not use the type
        # information.
        # We are only interested in cases where the symbol's type is actually used
        # by the plugin.
        continue
    fi
    echo $IMAGE $plugin
    vol \
        -f "/io/dumps/$IMAGE" $plugin |
        sed -En 's/^GREPME (.*?)$/\1/p' |
        sort -u |
        tee "${OFILE}_${plugin}"
done

cat $OFILE* | sort -u >$OFILE

exit 0
