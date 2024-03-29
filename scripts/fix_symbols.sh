#!/usr/bin/env bash

set -xeuo pipefail

if [[ $# != 1 ]]; then
    echo "Fixes symbol files generated by dwarf2json that are missing"
    echo "the long unsigned int basic type."
    echo "Usage: $0 <isf file>"
fi

ifile="$1"
ofile=/tmp/$(basename "$ifile")

pattern='    "unsigned int": \{
      "size": 4,
      "signed": false,
      "kind": "int",
      "endian": "little"
    \},\n'

ins='    "long unsigned int": {
      "size": 8,
      "signed": false,
      "kind": "int",
      "endian": "little"
    },'

pos=$(rg --multiline --only-matching --byte-offset "$pattern" "$ifile")
pos=${pos%%:*}
head -c $pos "$ifile" >"$ofile"
echo -n "$ins" >>"$ofile"
tail -c+$pos "$ifile" >>"$ofile"

yes | mv "$ofile" "$ifile"
