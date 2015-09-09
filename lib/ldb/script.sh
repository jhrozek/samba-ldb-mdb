#!/bin/bash

pushd /home/remote/jhrozek/devel/samba/lib/ldb
rm -f ./mdbtest
gcc tests/apitest.c -ltalloc -lcmocka -ltevent -lldb -g -o mdbtest
LDB_MODULES_PATH=./bin LD_PRELOAD=./bin/shared/libldb.so.1 ./mdbtest
popd
