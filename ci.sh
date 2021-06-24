#!/bin/bash
set -e -x -o pipefail
cd test

pushd auth
./test.sh
popd

pushd gridfs
./test.sh
popd
