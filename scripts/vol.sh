#!/usr/bin/env bash

set -euo pipefail

VOL_BASE=/opt/vol/volatility3/volatility3
VOL_SYM=${VOL_BASE}/symbols/linux
# note: There seems to be a problem with importing a python module via
# 	importlib if the backing file is on a docker mount -> we have to
# 	mount and copy the plugins :(
VOL_PLUG=${VOL_BASE}/plugins/linux
VOL_UTIL=${VOL_BASE}/utility
VOL_CACHE=/root/.cache/volatility3
VOL_VER=2.5.0

PLUG="$(pwd)/src/plugins"
UTIL="$(pwd)/src/utility"
PATCH="$(pwd)/src/patches"
SYM="$(pwd)/io/symbols"
CACHE="$(pwd)/io/cache"
BASH_HISTORY="$(pwd)/.bash_history"
BASH_RC="$(pwd)/scripts/bashrc"

test -e "$BASH_HISTORY" || touch "$BASH_HISTORY"
test -e "$BASH_RC" || exit 1

function print_usage {
  echo "Available options:
  -h,--help: Print this help string and exit
  -r,--run: Run the analysis container
  -p,--pull: Pull the latest container image from dockerhub
  -s,--shell: Get a shell in the running analysis container
  -b,--build: Build the analysis container
  -d,--debug: Enable debug output"
}

while (("$#")); do
	case "$1" in
	-r | --run)
		# Run the vol container
		docker run 					\
		  --name BPFVol3_analysis			\
		  --rm 						\
		  -it 						\
		  -v "$(pwd)/io:/io" 				\
		  -v "${PLUG}:/plug"				\
		  -v "${UTIL}:${VOL_UTIL}"			\
		  -v "${PATCH}:/patches"			\
		  -v "${SYM}:${VOL_SYM}"			\
		  -v "${CACHE}:${VOL_CACHE}"			\
		  -v "$(pwd)/scripts/container_init:/bin/container_init" \
		  -v "${BASH_HISTORY}:/root/.bash_history"      \
		  -v "${BASH_RC}:/root/.bashrc"        		\
		  -e VOL_VER=${VOL_VER}				\
		  -w="${VOL_BASE}/.." 				\
		  bpfvol3:latest				\
		  /bin/container_init				|| \
		exit 1

		exit 0
		;;
	-s | --shell)
		# Run a shell in the vol container
		CID=$(docker container list -lq)
		docker exec                                     \
		  -it                                           \
		  ${CID}                                        \
		  /bin/bash					|| \
		exit 1

		exit 0
		;;
	-b | --build)
	  	# Build the vol container
	        docker build 					\
		  --build-arg VOL_VER=${VOL_VER}		\
		  -t bpfvol3:latest 				\
		  - < ./scripts/dockerfile_vol

		exit 0
		;;
	-p | --pull)
		# Pull the latest container image from dockerhub
		echo "Not implemented :("
		exit 42
		;;
	-d | --debug)
		# Enable debug output
		set -euxo pipefail
		shift 1
		;;
	-h | --help)
		# Print usage info
		print_usage
		exit 0
		;;
	-*)
		echo "Error: Unknown option: $1" >&2
		print_usage >&2
		exit 1
		;;
	*) # No more options
		break
		;;
	esac
done
