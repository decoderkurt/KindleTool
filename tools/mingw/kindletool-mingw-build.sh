#! /bin/bash -e
#
# KindleTool cross mingw buildscript
#
##

## Install/Setup CrossTool-NG
Build_CT-NG() {
	echo "* Building CrossTool-NG . . ."
	echo ""

	# Get out of our git tree
	cd ../../..

	# Make us a dedicated sysroot
	mkdir -p MinGW
	cd MinGW

	mkdir -p CT-NG
	cd CT-NG
	hg clone http://crosstool-ng.org/hg/crosstool-ng .
	# Bump MinGW API & RT to latest versions
	# FIXME: Broken right now, cf. http://sourceforge.net/tracker/?func=detail&atid=102435&aid=3441135&group_id=2435
	patch -p1 < ../../KindleTool/tools/mingw/ct-ng-mingw-vbump.patch
	# The default versions build okay, but let's use mingw-w64 instead... (http://mingw-w64.sourceforge.net/)

	./bootstrap
	./configure --prefix=/home/niluje/Kindle/KTool_Static/MinGW/CT
	make
	make install
	export PATH="${PATH}:/home/niluje/Kindle/KTool_Static/MinGW/CT/bin"

	cd ..
	mkdir -p Build_TC
	cd Build_TC

	ct-ng distclean
	unset CFLAGS CXXFLAGS LDFLAGS

	cp ../../KindleTool/tools/mingw/ct-ng_mingw_dot.config .config
	ct-ng oldconfig
	#ct-ng menuconfig

	## Config:
	cat << EOF

	CT-NG Config Overview:

	* Paths >
	EXPERIMENTAL: [*]
	Parallel jobs: 3

	* Target >
	Arch: x86
	Bitness: 32-bit
	Arch level: i686
	CPU: i686
	Tune: i686
	CFLAGS: -O2 -fomit-frame-pointer -pipe

	* TC >
	Tuple's vendor: pc

	* OS >
	Target: mingw32
	Win API: 3.17-2

	* Binary >
	Format: ELF			# Don't mind this, we really will end up with Win PE binaries ;)
	Binutils: 2.22
	Linkers to enable: ld

	* C Compiler >
	Type: gcc
	Version: 4.6.3
	Additional Lang: C++
	Link lstdc++ statically
	Enable GRAPHITE
	Enable LTO
	Opt gcc libs for size [ ]
	Use __cxa_atexit
	<M> sjlj
	<M> 128-bit long doubles

	* C library >
	Type: mingw
	MinGW RT: 3.20-2
	Threading: win32

EOF
	##

	nice ct-ng build
}

## I'd use this TC: http://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win32/Personal%20Builds/rubenvb/gcc-4.7-release/
## but they're actually for an x86_64 Linux host, not x86, so, fallback to the automated builds on my x86 box... (Or use http://code.google.com/p/mingw-w64-dgn/)

# Make sure we're up to date
git pull

echo "* Setting environment up . . ."
echo ""
ARCH_FLAGS="-march=i686 -mtune=i686"
CROSS_TC="i686-w64-mingw32"
TC_BUILD_DIR="/home/niluje/Kindle/KTool_Static/MinGW/Build_W32"

export PATH="/home/niluje/x-tools/mingw32/bin:${PATH}"

BASE_CFLAGS="-O2 -ffast-math ${ARCH_FLAGS} -pipe -fomit-frame-pointer"
export CFLAGS="${BASE_CFLAGS}"
export CXXFLAGS="${BASE_CFLAGS}"
BASE_CPPFLAGS="-isystem${TC_BUILD_DIR}/include"
export CPPFLAGS="${BASE_CPPFLAGS}"
BASE_LDFLAGS="-L${TC_BUILD_DIR}/lib -Wl,-O1 -Wl,--as-needed"
export LDFLAGS="${BASE_LDFLAGS}"

BASE_PKG_CONFIG_PATH="${TC_BUILD_DIR}/lib/pkgconfig"
BASE_PKG_CONFIG_LIBDIR="${TC_BUILD_DIR}/lib/pkgconfig"
export PKG_CONFIG_DIR=
export PKG_CONFIG_PATH="${BASE_PKG_CONFIG_PATH}"
export PKG_CONFIG_LIBDIR="${BASE_PKG_CONFIG_LIBDIR}"

## Go :)
## Get to our build dir
mkdir -p "${TC_BUILD_DIR}"
KT_TOOLS_DIR="${PWD}/.."
cd "${TC_BUILD_DIR}"

ZLIB_VER="1.2.8"
ZLIB_DIR="zlib-${ZLIB_VER}"
ZLIB_FILE="zlib${ZLIB_VER//.}.zip"
GMP_VER="5.1.3"
GMP_DIR="gmp-${GMP_VER}"
NETTLE_VER="2.7.1"
NETTLE_DIR="nettle-${NETTLE_VER}"
LIBARCHIVE_VER="3.1.2"
LIBARCHIVE_DIR="libarchive-${LIBARCHIVE_VER}"

if [[ ! -d "${ZLIB_DIR}" ]] ; then
	echo "* Building zlib . . ."
	echo ""
	if [[ ! -f "./${ZLIB_FILE}" ]] ; then
		wget -O "${ZLIB_FILE}" "http://zlib.net/${ZLIB_FILE}"
	fi
	unzip ./${ZLIB_FILE}
	cd ${ZLIB_DIR}
	patch -p1 < ../../../KindleTool/tools/mingw/zlib-1.2.7-mingw-makefile-fix.patch
	make -f win32/Makefile.gcc
	mkdir -p ${TC_BUILD_DIR}/include ${TC_BUILD_DIR}/bin ${TC_BUILD_DIR}/lib
	#cp -v zlib1.dll ${TC_BUILD_DIR}/bin
	cp -v zconf.h zlib.h ${TC_BUILD_DIR}/include
	cp -v libz.a ${TC_BUILD_DIR}/lib
	#cp -v libz.dll.a ${TC_BUILD_DIR}/lib
	cd ..
fi

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
	./configure --prefix="${TC_BUILD_DIR}" --host="${CROSS_TC}" --enable-static --disable-shared --disable-cxx
	make -j2
	make install
	cd ..
fi

# nettle
if [[ "${USE_STABLE_NETTLE}" == "true" ]] ; then
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
		./configure --prefix="${TC_BUILD_DIR}" --libdir="${TC_BUILD_DIR}/lib" --host="${CROSS_TC}" --enable-static --disable-shared --enable-public-key --disable-openssl --disable-documentation
		make -j2
		make install
		cd ..
	fi
else
	# Build from git to benefit from the more x86_64 friendly API changes
	if [[ ! -d "nettle-git" ]] ; then
		echo "* Building nettle . . ."
		echo ""
		git clone git://git.lysator.liu.se/nettle/nettle.git nettle-git
		cd nettle-git
		sed -e '/CFLAGS=/s: -ggdb3::' -e 's/solaris\*)/sunldsolaris*)/' -i configure.ac
		sed -i '/SUBDIRS/s/testsuite examples//' Makefile.in
		# Fix MinGW builds...
		sed -e 's#desdata$(EXEEXT)#desdata$(EXEEXT_FOR_BUILD)#g' -i Makefile.in
		sh ./.bootstrap
		./configure --prefix="${TC_BUILD_DIR}" --libdir="${TC_BUILD_DIR}/lib" --host="${CROSS_TC}" --enable-static --disable-shared --enable-public-key --disable-openssl --disable-documentation
		make -j2
		make install
		cd ..
	fi
fi

# libarchive
if [[ "${USE_STABLE_LIBARCHIVE}" == "true" ]] ; then
	if [[ ! -d "${LIBARCHIVE_DIR}" ]] ; then
		echo "* Building ${LIBARCHIVE_DIR} . . ."
		echo ""
		if [[ ! -f "./${LIBARCHIVE_DIR}.tar.gz" ]] ; then
			wget -O "./${LIBARCHIVE_DIR}.tar.gz" "http://github.com/libarchive/libarchive/archive/v${LIBARCHIVE_VER}.tar.gz"
		fi
		tar -xvzf ./${LIBARCHIVE_DIR}.tar.gz
		cd ${LIBARCHIVE_DIR}
		./build/autogen.sh
		./configure --prefix="${TC_BUILD_DIR}" --host="${CROSS_TC}" --enable-static --disable-shared --disable-xattr --disable-acl --with-zlib --without-bz2lib --without-lzmadec --without-iconv --without-lzma --without-nettle --without-openssl --without-expat --without-xml2
		make -j2
		make install
		cd ..
	fi
else
	if [[ ! -d "libarchive-git" ]] ; then
		echo "* Building libarchive . . ."
		echo ""
		git clone https://github.com/libarchive/libarchive.git libarchive-git
		cd libarchive-git
		patch -p1 < ${KT_TOOLS_DIR}/libarchive-fix-issue-317.patch
		# Remove -Werror, there might be some warnings depending on the TC used...
		sed -e 's/-Werror //' -i ./Makefile.am
		./build/autogen.sh
		./configure --prefix="${TC_BUILD_DIR}" --host="${CROSS_TC}" --enable-static --disable-shared --disable-xattr --disable-acl --with-zlib --without-bz2lib --without-lzmadec --without-iconv --without-lzma --without-nettle --without-openssl --without-expat --without-xml2
		make -j2
		make install
		cd ..
	fi
fi

# Build KT package credits
cat > ../../CREDITS << EOF
* kindletool.exe: KindleTool, Copyright (C) 2011-2013  Yifan Lu, licensed under the GNU General Public License version 3+ (http://www.gnu.org/licenses/gpl.html).
(https://github.com/NiLuJe/KindleTool/)

  |->   zlib, Copyright (C) 1995-2012 Jean-loup Gailly and Mark Adler,
  |   Licensed under the zlib license (http://zlib.net/zlib_license.html)
  |   (http://zlib.net/)
  |
  |->   libarchive, Copyright (C) Tim Kientzle, licensed under the New BSD License (http://www.opensource.org/licenses/bsd-license.php)
  |   (http://libarchive.github.com/)
  |
  |->   GMP, GNU MP Library, Copyright 1991-2013 Free Software Foundation, Inc.,
  |   licensed under the GNU Lesser General Public License version 3+ (http://www.gnu.org/licenses/lgpl.html).
  |   (http://gmplib.org/)
  |
  |->   nettle, Copyright (C) 2001-2013 Niels Möller,
  |   licensed under the GNU Lesser General Public License version 2.1+ (https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html).
  |   (http://www.lysator.liu.se/~nisse/nettle)
  |
  \`->   Built using MinGW-w64 and statically linked against the MinGW-w64 runtime, Copyright (C) 2009, 2010 by the mingw-w64 project,
      Licensed mostly under the Zope Public License (ZPL) Version 2.1. (http://sourceforge.net/apps/trac/mingw-w64/browser/tags/v2.0.4/COPYING.MinGW-w64-runtime/COPYING.MinGW-w64-runtime.txt)
      (http://mingw-w64.sourceforge.net/)
EOF

# KindleTool
echo "* Building KindleTool . . ."
echo ""
cd ../..
cd KindleTool/KindleTool
rm -rf lib includes
make clean
make mingw

# Package it
git log --stat --graph > ../../ChangeLog
./version.sh PMS
VER_FILE="VERSION"
VER_CURRENT="$(<${VER_FILE})"
# Strip the git commit
REV="${VER_CURRENT%%-*}"
#REV="${VER_CURRENT}"
cd ../..
cp -v KindleTool/KindleTool/MinGW/kindletool.exe ./kindletool.exe
cp -v KindleTool/README.md ./README
# Quick! Markdown => plaintext
sed -si 's/<b>//g;s/<\/b>//g;s/<i>//g;s/<\/i>//g;s/&lt;/</g;s/&gt;/>/g;s/&amp;/&/g;s/^* /  /g;s/*//g;s/>> /\t/g;s/^> /  /g;s/^## //g;s/### //g;s/\t/    /g;s/^\([[:digit:]]\)\./  \1)/g;s/^#.*$//;s/[[:blank:]]*$//g' README
mv -v KindleTool/KindleTool/VERSION ./VERSION
# LF => CRLF...
unix2dos CREDITS README ChangeLog
7z a -tzip kindletool-${REV}-mingw.zip kindletool.exe CREDITS README ChangeLog VERSION
rm -f kindletool.exe CREDITS README ChangeLog VERSION

