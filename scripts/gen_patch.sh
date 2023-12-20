#!/usr/bin/env bash

set -euxo pipefail

cd ./volatility3

COMMIT=$(git rev-parse HEAD)

git diff >../src/patches/${COMMIT}.patch
