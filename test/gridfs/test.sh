#!/usr/bin/env bash

set -e -o pipefail

if [[ ! -x "$(which rdmd)" && ! -x ./test_gridfs ]] ; then
  echo Cannot find rdmd in the path or a ./test_gridfs binary.  Try 'make' in a dev environment.
  exit 1
fi

dd if=/dev/urandom of=small.bin bs=1K count=1
dd if=/dev/urandom of=large.bin bs=1M count=100

mongofiles -d test_files -r put small.bin
mongofiles -d test_files -r put large.bin

cleanup() {
  mongofiles -d test_files delete small.bin
  mongofiles -d test_files delete large.bin

  rm -f small.bin large.bin
}
trap cleanup EXIT

if [[ -x ./test_gridfs ]] ; then
  ./test_gridfs small.bin $(sha1sum small.bin | cut -d ' ' -f 1)
  ./test_gridfs large.bin $(sha1sum large.bin | cut -d ' ' -f 1)
else
  rdmd -g -I../../source test_gridfs.d small.bin $(sha1sum small.bin | cut -d ' ' -f 1)
  rdmd -g -I../../source test_gridfs.d large.bin $(sha1sum large.bin | cut -d ' ' -f 1)
fi
