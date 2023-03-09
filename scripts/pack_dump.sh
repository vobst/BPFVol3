#!/usr/bin/env bash

set -exuo pipefail

if [[ $# != 1 ]]
then
  echo "usage: $0 <relative path to file>"
  exit 1
fi

file="$(pwd)/$1"
filename=$(basename -- "$file")
extension="${filename##*.}"
if [[ $extension = $filename ]]
then
  extension=".bin"
fi
filehash=$(md5sum $file | rg '([0-9a-f]+?) ' -r '$1' -o)

7z a -t7z "/tmp/$filehash.7z" "$file"
7za rn "/tmp/$filehash.7z" $(basename $file) "$filehash.$extension"
