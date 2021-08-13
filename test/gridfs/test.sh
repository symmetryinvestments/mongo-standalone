#!/usr/bin/env bash

set -e -o pipefail

if [[ ! -x "$(which rdmd)" && ! -x ./test_gridfs ]] ; then
  echo Cannot find rdmd in the path or a ./test_gridfs binary.  Try 'make' in a dev environment.
  exit 1
fi

# test single retrieval for a large and a small file
dd if=/dev/urandom of=small.bin bs=1K count=1
dd if=/dev/urandom of=large.bin bs=1M count=100

cleanup() {
    for file in `ls *.bin`; do
	mongofiles --quiet -d test_files delete $file >/dev/null
	rm -f $file
    done
}
trap cleanup EXIT

mongofiles --quiet -d test_files -r put small.bin
mongofiles --quiet -d test_files -r put large.bin

if [[ -x ./test_gridfs ]] ; then
  ./test_gridfs small.bin $(sha1sum small.bin | cut -d ' ' -f 1)
  ./test_gridfs large.bin $(sha1sum large.bin | cut -d ' ' -f 1)
else
  rdmd -g -I../../source test_gridfs.d small.bin $(sha1sum small.bin | cut -d ' ' -f 1)
  rdmd -g -I../../source test_gridfs.d large.bin $(sha1sum large.bin | cut -d ' ' -f 1)
fi

# test retrieval of many small files
dd if=/dev/urandom of=many.bin bs=1M count=100
split -b 100000 --additional-suffix .bin many.bin many
for file in `ls many*.bin`; do
    mongofiles --quiet -d test_files -r put $file >/dev/null
done

if [[ -x ./test_gridfs_many ]] ; then
    ls many*.bin | xargs ./test_gridfs_many
else
    ls many*.bin | xargs rdmd -g -I../../source test_gridfs_many.d
fi
