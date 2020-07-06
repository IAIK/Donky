#!/bin/bash

if [[ ! -f "$1" ]]; then
  echo "File $1 does not exist"
  exit 1
fi

set -e
echo "Patching (1/3) $1"
grep "===" "$1" && awk -f strip_linker.awk "$1" > "$1.patched" || cp "$1" "$1.patched"

# sed options:
# -i ... in-place
# -z ... multi-line matching
# 
# Insert __tls_static_start at beginning of .tdata
echo "Patching (2/3) $1"
sed -i -zre "s/(\s*\.tdata\s*:\s*\{)/\1\n    __tls_static_start = .;\n/" "$1.patched"

# Insert __tls_static_end at end of .tbss
echo "Patching (3/3) $1"

sed -i -zre "s/(\s*\.tbss\s*:\s*\{)([^\}]*)\}/\1\n    \2\n    __tls_static_end = .;\n  \}/" "$1.patched"
mv "$1.patched" "$1"
rm -f $1.patched
