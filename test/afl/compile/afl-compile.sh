#!/bin/sh -x

. ./compile/fcns

### set either afl-gcc or afl-clang (defaults to afl-gcc)
set_afl_cc

cd ../../

CC=$AFL_CC ./extras/apparmor/configure_args.sh --enable-afl-fuzzing $@

if [ $? -ne 0 ]
then
    echo "[*] autogen configure script failure, exiting"
    exit 1
fi

make clean
AFL_HARDEN=1 make
cd test/afl
exit $?
