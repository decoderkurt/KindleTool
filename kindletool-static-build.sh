#!/bin/bash

OSTYPE="$(uname -s)"	# FIXME: Check that it's correct for Cygwin, or use uname -o (and fix version.sh if needed, while we're at it)

case "${OSTYPE}" in
	"Linux" )
		Build_Linux
	;;
	"Cygwin" )
		Build_Cygwin
	;;
	"Darwin" )
		Build_OSX
	;;
	* )
		echo "Unknown OS: ${OSTYPE}"
		exit 1
	;;
esac

## Linux!
Build_Linux() {
	echo "* Preparing a static KindleTool build on Linux . . ."
	export CFLAGS="-march=i686 -pipe -O2 -fomit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE"
	export CXXFLAGS="-march=i686 -pipe -O2 -fomit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE"
	export LDFLAGS="-Wl,-O1 -Wl,--as-needed"

	OPENSSL_DIR="openssl-0.9.8w"
	LIBARCHIVE_DIR="libarchive-3.0.4"

	# Make sure we're up to date
	git pull

	# Get out of our git tree
	cd ..

	# OpenSSL: pretty much the same way as in my arm builds
	if [[ ! -d "${OPENSSL_DIR}" ]] ; then
		echo "* Building ${OPENSSL_DIR} . . ."
		echo ""
		export LDFLAGS="-Wa,--noexecstack"
		tar -xvzf /usr/portage/distfiles/${OPENSSL_DIR}.tar.gz
		cd ${OPENSSL_DIR}
		patch -p1 < /usr/portage/dev-libs/openssl/files/openssl-0.9.8e-bsd-sparc64.patch
		patch -p1 < /usr/portage/dev-libs/openssl/files/openssl-0.9.8h-ldflags.patch
		patch -p1 < /usr/portage/dev-libs/openssl/files/openssl-0.9.8m-binutils.patch
		sed -i -e '/DIRS/s: fips : :g' -e '/^MANSUFFIX/s:=.*:=ssl:' -e '/^MAKEDEPPROG/s:=.*:=gcc:' -e '/^install:/s:install_docs::' Makefile{,.org}
		sed -i '/^SET_X/s:=.*:=set -x:' Makefile.shared
		cp /usr/portage/dev-libs/openssl/files/gentoo.config-0.9.8 gentoo.config
		chmod a+rx gentoo.config
		sed -i '1s,^:$,#!/usr/bin/perl,' Configure
		sed -i '/^"debug-steve/d' Configure
		./Configure linux-generic32 -DL_ENDIAN -O2 -march=i686 -pipe -O2 -fomit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE -fno-strict-aliasing enable-camellia enable-mdc2 enable-tlsext enable-zlib shared threads
		grep '^CFLAG=' Makefile | LC_ALL=C sed -e 's:^CFLAG=::' -e 's:-ffast-math ::g' -e 's:-fomit-frame-pointer ::g' -e 's:-O[0-9] ::g' -e 's:-march=[-a-z0-9]* ::g' -e 's:-mcpu=[-a-z0-9]* ::g' -e 's:-m[a-z0-9]* ::g' >| x-compile-tmp
		CFLAG="$(< x-compile-tmp)"
		sed -i -e "/^CFLAG/s:=.*:=${CFLAG} ${CFLAGS}:" -e "/^SHARED_LDFLAGS=/s:$: ${LDFLAGS}:" Makefile
		make -j1 depend
		make -j1 build_libs
		cd ..
	fi

	# libarchive
	if [[ ! -d "${LIBARCHIVE_DIR}" ]] ; then
		echo "* Building ${LIBARCHIVE_DIR} . . ."
		echo ""
		export ac_cv_header_ext2fs_ext2_fs_h=0
		export LDFLAGS="-Wl,-O1 -Wl,--as-needed"
		tar -xvzf /usr/portage/distfiles/${LIBARCHIVE_DIR}.tar.gz
		cd ${LIBARCHIVE_DIR}
		./configure --enable-static --disable-shared --disable-xattr --disable-acl --with-zlib --without-bz2lib --without-lzmadec --without-iconv --without-lzma --without-nettle --without-expat --without-xml2
		make
		cd ..
	fi

	# Build KT packages credits
	cat > CREDITS << EOF
* kindletool:

KindleTool, Copyright (C) 2011-2012  Yifan Lu, licensed under the GNU General Public License version 3+ (http://www.gnu.org/licenses/gpl.html).
(https://github.com/NiLuJe/KindleTool/)

libarchive, Copyright (C) Tim Kientzle, licensed under the New BSD License (http://www.opensource.org/licenses/bsd-license.php)
(http://libarchive.github.com/)
EOF

	# KindleTool (OpenSSL-1)
	echo "* Building KindleTool (OpenSSL-1) . . ."
	echo ""
	export LDFLAGS="-Llib -Wl,-O1 -Wl,--as-needed"
	cd KindleTool/KindleTool
	rm -rf lib
	mkdir -p lib
	cp ../../${LIBARCHIVE_DIR}/.libs/libarchive.a lib
	make clean
	make strip

	# Package it
	git log --stat --graph > ../../ChangeLog
	./version.sh PMS
	VER_FILE="VERSION"
	VER_CURRENT="$(<${VER_FILE})"
	REV="${VER_CURRENT%%-*}"
	cd ../..
	cp -v KindleTool/KindleTool/Release/kindletool ./kindletool
	cp -v KindleTool/README.md ./README
	# Quick! Markdown => plaintext
	sed -si 's/&lt;/</g;s/&gt;/>/g;s/&amp;/&/g;s/^* /  /g;s/*//g;s/>> /\t/g;s/^> /  /g;s/^## //g;s/### //g;s/\t/    /g;s/^\([[:digit:]]\)\./  \1)/g;s/^#.*$//;s/[[:blank:]]*$//g' README
	cp -v KindleTool/KindleTool/kindletool.1 ./kindletool.1
	mv -v KindleTool/KindleTool/VERSION ./VERSION
	tar -cvzf kindletool-${REV}-static.tar.gz kindletool CREDITS README kindletool.1 ChangeLog VERSION


	# KindleTool (OpenSSL-0.9.8)
	echo "* Building KindleTool (OpenSSL-0.9.8) . . ."
	echo ""
	cd KindleTool/KindleTool
	rm -rf lib
	mkdir -p lib
	cp ../../${LIBARCHIVE_DIR}/.libs/libarchive.a lib
	cp ../../${OPENSSL_DIR}/libcrypto.so.0.9.8 lib
	cd lib
	ln -sf libcrypto.so.0.9.8 libcrypto.so
	cd ..
	make clean
	make strip

	# Package it
	git log --stat --graph > ../../ChangeLog
	./version.sh PMS
	VER_FILE="VERSION"
	VER_CURRENT="$(<${VER_FILE})"
	REV="${VER_CURRENT%%-*}"
	cd ../..
	cp -v KindleTool/KindleTool/Release/kindletool ./kindletool
	cp -v KindleTool/README.md ./README
	# Quick! Markdown => plaintext
	sed -si 's/&lt;/</g;s/&gt;/>/g;s/&amp;/&/g;s/^* /  /g;s/*//g;s/>> /\t/g;s/^> /  /g;s/^## //g;s/### //g;s/\t/    /g;s/^\([[:digit:]]\)\./  \1)/g;s/^#.*$//;s/[[:blank:]]*$//g' README
	cp -v KindleTool/KindleTool/kindletool.1 ./kindletool.1
	mv -v KindleTool/KindleTool/VERSION ./VERSION
	tar -cvzf kindletool-${REV}-static-openssl-0.9.8.tar.gz kindletool CREDITS README kindletool.1 ChangeLog VERSION
}

# Win32 !
Build_Cygwin() {
	echo "* Preparing a static KindleTool build on Cygwin . . ."
	export CFLAGS="-march=i686 -pipe -O2 -fomit-frame-pointer"
	export CXXFLAGS="-march=i686 -pipe -O2 -fomit-frame-pointer"
	export LDFLAGS="-Wl,-O1 -Wl,--as-needed"

	LIBARCHIVE_DIR="libarchive-3.0.4"

	# Make sure we're up to date
	git pull

	# Get out of our git tree
	cd ..

	# libarchive
	if [[ ! -d "${LIBARCHIVE_DIR}" ]] ; then
		echo "* Building ${LIBARCHIVE_DIR} . . ."
		echo ""
		tar -xvzf ~/${LIBARCHIVE_DIR}.tar.gz
		cd ${LIBARCHIVE_DIR}
		./configure --prefix=/usr --enable-static --enable-shared --disable-xattr --disable-acl --with-zlib --without-bz2lib --without-lzmadec --without-iconv --without-lzma --without-nettle --without-expat --without-xml2
		make
		make install
		cd ..
	fi

	# Build KT packages credits
	cat > CREDITS << EOF
* kindletool:

KindleTool, Copyright (C) 2011-2012  Yifan Lu, licensed under the GNU General Public License version 3+ (http://www.gnu.org/licenses/gpl.html).
(https://github.com/NiLuJe/KindleTool/)

libarchive, Copyright (C) Tim Kientzle, licensed under the New BSD License (http://www.opensource.org/licenses/bsd-license.php)
(http://libarchive.github.com/)
EOF

	# KindleTool (OpenSSL-1)
	echo "* Building KindleTool . . ."
	echo ""
	## FIXME: Move dynamic libraries...
	rm -rf lib
	mkdir -p lib
	cp ../../${LIBARCHIVE_DIR}/.libs/libarchive.a lib	# Check the filenames...
	cd KindleTool/KindleTool
	make clean
	make strip
	## FIXME: Restore dynamic libraries...

	# Package it
	git log --stat --graph > ../../ChangeLog
	./version.sh PMS
	VER_FILE="VERSION"
	VER_CURRENT="$(<${VER_FILE})"
	REV="${VER_CURRENT%%-*}"
	cd ../..
	cp -v KindleTool/KindleTool/Release/kindletool ./kindletool
	cp -v KindleTool/README.md ./README
	# Quick! Markdown => plaintext
	sed -si 's/&lt;/</g;s/&gt;/>/g;s/&amp;/&/g;s/^* /  /g;s/*//g;s/>> /\t/g;s/^> /  /g;s/^## //g;s/### //g;s/\t/    /g;s/^\([[:digit:]]\)\./  \1)/g;s/^#.*$//;s/[[:blank:]]*$//g' README
	mv -v KindleTool/KindleTool/VERSION ./VERSION
	tar -cvzf kindletool-${REV}-cygwin.tar.gz kindletool CREDITS README ChangeLog VERSION
}

# OS X !
Build_OSX() {
	echo "* Preparing a static KindleTool build on OS X . . ."
	export CFLAGS="-march=core2 -pipe -O2 -fomit-frame-pointer"
	export CXXFLAGS="-march=core2 -pipe -O2 -fomit-frame-pointer"
	export LDFLAGS=""

	LIBARCHIVE_DIR="libarchive-3.0.4"

	# Make sure we're up to date
	git pull

	# Get out of our git tree
	cd ..

	# libarchive
	if [[ ! -d "${LIBARCHIVE_DIR}" ]] ; then
		echo "* Building ${LIBARCHIVE_DIR} . . ."
		echo ""
		tar -xvzf ~/${LIBARCHIVE_DIR}.tar.gz
		cd ${LIBARCHIVE_DIR}
		./configure --prefix=/opt/local --enable-static --enable-shared --disable-xattr --disable-acl --with-zlib --without-bz2lib --without-lzmadec --without-iconv --without-lzma --without-nettle --without-expat --without-xml2
		make
		cd ..
	fi

	# Build KT packages credits
	cat > CREDITS << EOF
* kindletool:

KindleTool, Copyright (C) 2011-2012  Yifan Lu, licensed under the GNU General Public License version 3+ (http://www.gnu.org/licenses/gpl.html).
(https://github.com/NiLuJe/KindleTool/)

libarchive, Copyright (C) Tim Kientzle, licensed under the New BSD License (http://www.opensource.org/licenses/bsd-license.php)
(http://libarchive.github.com/)
EOF

	# KindleTool (OpenSSL-1)
	echo "* Building KindleTool . . ."
	echo ""
	## FIXME: Move dynamic libraries (MacPorts)...
	cd KindleTool/KindleTool
	make clean
	make strip	# FIXME: If strip doesn't horribly breaks mach-o binaries...
	## FIXME: Restore dynamic libraries (MacPorts)...

	# Package it
	git log --stat --graph > ../../ChangeLog
	./version.sh PMS
	VER_FILE="VERSION"
	VER_CURRENT="$(<${VER_FILE})"
	REV="${VER_CURRENT%%-*}"
	cd ../..
	cp -v KindleTool/KindleTool/Release/kindletool ./kindletool
	cp -v KindleTool/README.md ./README
	# Quick! Markdown => plaintext
	sed -si 's/&lt;/</g;s/&gt;/>/g;s/&amp;/&/g;s/^* /  /g;s/*//g;s/>> /\t/g;s/^> /  /g;s/^## //g;s/### //g;s/\t/    /g;s/^\([[:digit:]]\)\./  \1)/g;s/^#.*$//;s/[[:blank:]]*$//g' README
	cp -v KindleTool/KindleTool/KindleTool.1 ./KindleTool.1
	mv -v KindleTool/KindleTool/VERSION ./VERSION
	tar -cvzf kindletool-${REV}-osx.tar.gz kindletool CREDITS README KindleTool.1 ChangeLog VERSION
}
