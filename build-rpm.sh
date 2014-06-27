#!/bin/sh

set -e

MYDIR="$(dirname $(readlink -m $0))"

if [ -d "rpm" ]; then
	echo "A folder called rpm already exists, please delete it before running this script."
	exit 1
fi

mkdir rpm

TOPDIR="$(readlink -m rpm)"

rpmbuild -bb --define "%s3proxy_intree_build 1" --define "%_topdir $TOPDIR" --define "%_sourcedir $MYDIR" $MYDIR/s3proxy.spec

echo "RPM built in $TOPDIR/RPMS"
