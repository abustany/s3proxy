#!/bin/sh

MYDIR="$(dirname $(readlink -m $0))"

mkdir -p rpm

TOPDIR="$(readlink -m rpm)"

rpmbuild -bb --define "%_topdir $TOPDIR" --define "%_sourcedir $MYDIR" $MYDIR/s3proxy.spec
