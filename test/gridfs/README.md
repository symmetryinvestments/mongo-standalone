## GridFS Test Notes

Assumes a Linux environment with:
 - `dub` and `dmd` available.
 - MongoDB installed locally with no authentication mechanism necessary.
 - `mongofiles` utility available.

Of course multiple containers with different environments may be used, one for D development and
another for MongoDB.

These tests use a DB called `test_files`.  This will in turn make the GridFS bucket path
`test_files.fs` which is used in the test code.  This may differ in other production DBs -- the path
used should be the one which contains `files` and `chunks`.

### Run

Run `make` to build a test binary, then run `test.sh`.

