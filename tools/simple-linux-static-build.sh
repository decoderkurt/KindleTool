#!/bin/bash -e
#
# Simple static build, using the host's OpenSSL.
# (Only libarchive will be built/statically linked).
#
##

OSTYPE="$(uname -s)"
ARCH="$(uname -m)"

## Linux!
Build_Linux() {
	echo "* Preparing a static KindleTool build on Linux . . ."
	unset CPPFLAGS	# Let the Makefile take care of it ;).
	export CFLAGS="-pipe -O2 -fomit-frame-pointer -march=native"
	export CXXFLAGS="-pipe -O2 -fomit-frame-pointer -march=native"
	if [[ "${ARCH}" == "x86_64" ]] ; then
		GMPABI="64"
	else
		GMPABI="32"
	fi

	GMP_VER="5.1.3"
	GMP_DIR="gmp-${GMP_VER}"
	NETTLE_VER="2.7.1"
	NETTLE_DIR="nettle-${NETTLE_VER}"
	LIBARCHIVE_VER="3.1.2"
	LIBARCHIVE_DIR="libarchive-${LIBARCHIVE_VER}"

	# Make sure we're up to date
	git pull

	# Get out of our git tree
	cd ../..

	KT_SYSROOT="${PWD}/kt-sysroot-lin-${ARCH}"
	# NOTE: Use -isystem so that gmp doesn't do crazy stuff...
	export CPPFLAGS="-isystem${KT_SYSROOT}/include"
	export LDFLAGS="-L${KT_SYSROOT}/lib -Wl,-O1 -Wl,--as-needed"

	# GMP
	if [[ ! -d "${GMP_DIR}" ]] ; then
		echo "* Building ${GMP_DIR} . . ."
		echo ""
		if [[ ! -f "./${GMP_DIR}.tar.xz" ]] ; then
			wget -O "./${GMP_DIR}.tar.xz" "http://ftp.gmplib.org/gmp/${GMP_DIR}.tar.xz"
		fi
		tar -xvJf ./${GMP_DIR}.tar.xz
		cd ${GMP_DIR}
		patch -p1 < /usr/portage/dev-libs/gmp/files/gmp-4.1.4-noexecstack.patch
		libtoolize
		./configure ABI=${GMPABI} --prefix="${KT_SYSROOT}" --enable-static --disable-shared --disable-cxx
		make -j2
		make install
		cd ..
	fi

	# nettle
	if [[ ! -d "${NETTLE_DIR}" ]] ; then
		echo "* Building ${NETTLE_DIR} . . ."
		echo ""
		if [[ ! -f "./${NETTLE_DIR}.tar.gz" ]] ; then
			wget -O "./${NETTLE_DIR}.tar.gz" "http://www.lysator.liu.se/~nisse/archive/${NETTLE_DIR}.tar.gz"
		fi
		tar -xvzf ./${NETTLE_DIR}.tar.gz
		cd ${NETTLE_DIR}
		sed -e '/CFLAGS=/s: -ggdb3::' -e 's/solaris\*)/sunldsolaris*)/' -i configure.ac
		sed -i '/SUBDIRS/s/testsuite examples//' Makefile.in
		autoreconf -fi
		./configure  --prefix="${KT_SYSROOT}" --enable-static --disable-shared --enable-public-key --disable-openssl --disable-documentation
		make -j2
		make install
		cd ..
	fi

	# libarchive
	if [[ ! -d "${LIBARCHIVE_DIR}" ]] ; then
		echo "* Building ${LIBARCHIVE_DIR} . . ."
		echo ""
		export ac_cv_header_ext2fs_ext2_fs_h=0
		if [[ ! -f "./${LIBARCHIVE_DIR}.tar.gz" ]] ; then
			wget -O "./${LIBARCHIVE_DIR}.tar.gz" "http://github.com/libarchive/libarchive/archive/v${LIBARCHIVE_VER}.tar.gz"
		fi
		tar -xvzf ./${LIBARCHIVE_DIR}.tar.gz
		cd ${LIBARCHIVE_DIR}
		./build/autogen.sh
		./configure --prefix="${KT_SYSROOT}" --enable-static --disable-shared --disable-xattr --disable-acl --with-zlib --without-bz2lib --without-lzmadec --without-iconv --without-lzma --without-nettle --without-openssl --without-expat --without-xml2
		make -j2
		make install
		unset ac_cv_header_ext2fs_ext2_fs_h
		cd ..
	fi

	# Build KT package credits
	cat > CREDITS << EOF
* kindletool:

KindleTool, Copyright (C) 2011-2013  Yifan Lu, licensed under the GNU General Public License version 3+ (http://www.gnu.org/licenses/gpl.html).
(https://github.com/NiLuJe/KindleTool/)

  |
  |->   libarchive, Copyright (C) Tim Kientzle, licensed under the New BSD License (http://www.opensource.org/licenses/bsd-license.php)
  |   (http://libarchive.github.com/)
  |
  |->   GMP, GNU MP Library, Copyright 1991-2013 Free Software Foundation, Inc.,
  |   licensed under the GNU Lesser General Public License version 3+ (http://www.gnu.org/licenses/lgpl.html).
  |   (http://gmplib.org/)
  |
  \`->   nettle, Copyright (C) 2001-2013 Niels Möller,
      licensed under the GNU Lesser General Public License version 2.1+ (https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html).
      (http://www.lysator.liu.se/~nisse/nettle)
EOF

	# KindleTool
	echo "* Building KindleTool . . ."
	echo ""
	cd KindleTool/KindleTool
	rm -rf lib includes
	make clean
	make strip

	# Package it
	git log --stat --graph > ../../ChangeLog
	./version.sh PMS
	VER_FILE="VERSION"
	VER_CURRENT="$(<${VER_FILE})"
	# Strip the git commit
	REV="${VER_CURRENT%%-*}"
	#REV="${VER_CURRENT}"
	cd ../..
	cp -v KindleTool/KindleTool/Release/kindletool ./kindletool
	cp -v KindleTool/README.md ./README
	# Quick! Markdown => plaintext
	sed -si 's/<b>//g;s/<\/b>//g;s/<i>//g;s/<\/i>//g;s/&lt;/</g;s/&gt;/>/g;s/&amp;/&/g;s/^* /  /g;s/*//g;s/>> /\t/g;s/^> /  /g;s/^## //g;s/### //g;s/\t/    /g;s/^\([[:digit:]]\)\./  \1)/g;s/^#.*$//;s/[[:blank:]]*$//g' README
	cp -v KindleTool/KindleTool/kindletool.1 ./kindletool.1
	mv -v KindleTool/KindleTool/VERSION ./VERSION
	tar -cvzf kindletool-${REV}-linux-${ARCH}.tar.gz kindletool CREDITS README kindletool.1 ChangeLog VERSION
	rm -f kindletool CREDITS README kindletool.1 ChangeLog VERSION
}

# Main
case "${OSTYPE}" in
	"Linux" )
		Build_Linux
	;;
	* )
		echo "Unknown OS: ${OSTYPE}"
		exit 1
	;;
esac
