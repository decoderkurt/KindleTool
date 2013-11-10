#!/bin/bash -e

OSTYPE="$(uname -s)"
ARCH="$(uname -m)"

## Linux!
Build_Linux() {
	echo "* Preparing a static KindleTool build on Linux . . ."
	if [[ "${ARCH}" == "x86_64" ]] ; then
		export CFLAGS="-march=core2 -pipe -O2 -fomit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE"
		export CXXFLAGS="-march=core2 -pipe -O2 -fomit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE"
		export GMPABI="64"
	else
		export CFLAGS="-march=i686 -pipe -O2 -fomit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE"
		export CXXFLAGS="-march=i686 -pipe -O2 -fomit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE"
		export GMPABI="32"
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
	export CPPFLAGS="-I${KT_SYSROOT}/include"
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
		export LDFLAGS="-Wl,-O1 -Wl,--as-needed"
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
	# Fake user@host tag
	if [[ "$(whoami)" == "niluje" ]] ; then
		export KT_NO_USERATHOST_TAG="true"
		if [[ "${ARCH}" == "x86_64" ]] ; then
			export CFLAGS="-march=core2 -pipe -O2 -fomit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE -DKT_USERATHOST='\"niluje@ajulutsikael\"'"
		else
			export CFLAGS="-march=i686 -pipe -O2 -fomit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE -DKT_USERATHOST='\"niluje@ajulutsikael\"'"
		fi
	fi
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

# Win32 !
Build_Cygwin() {
	echo "* Preparing a static KindleTool build on Cygwin . . ."
	export CFLAGS="-march=i686 -pipe -O2 -fomit-frame-pointer"
	export CXXFLAGS="-march=i686 -pipe -O2 -fomit-frame-pointer"
	export LDFLAGS="-Wl,-O1 -Wl,--as-needed"

	LIBARCHIVE_VER="3.1.2"
	LIBARCHIVE_DIR="libarchive-${LIBARCHIVE_VER}"

	# Make sure we're up to date
	git pull

	# Get out of our git tree
	cd ../..

	# libarchive
	if [[ ! -d "${LIBARCHIVE_DIR}" ]] ; then
		echo "* Building ${LIBARCHIVE_DIR} . . ."
		echo ""
		if [[ ! -f "./${LIBARCHIVE_DIR}.tar.gz" ]] ; then
			wget -O "./${LIBARCHIVE_DIR}.tar.gz" "http://github.com/libarchive/libarchive/archive/v${LIBARCHIVE_VER}.tar.gz"
		fi
		tar -xvzf ./${LIBARCHIVE_DIR}.tar.gz
		cd ${LIBARCHIVE_DIR}
		# NOTE: The win crypto stuff breaks horribly with the current Cygwin packages...
		# Switch to cmake, which will properly use OpenSSL on Cygwin, and hope it doesn't break everything, because the tests still fail horribly to build...
		cmake -DCMAKE_INSTALL_PREFIX="/usr" -DCMAKE_BUILD_TYPE="Release" -DENABLE_TEST=FALSE -DENABLE_NETTLE=FALSE -DENABLE_XATTR=FALSE -DENABLE_ACL=FALSE -DENABLE_ICONV=FALSE -DENABLE_CPIO=FALSE -DENABLE_TAR=ON -DENABLE_OPENSSL=ON
		make
		make install
		cd ..
	fi

	# Build KT package credits
	cat > CREDITS << EOF
* kindletool.exe:

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
	# Fake user@host tag
	if [[ "$(whoami)" == "NiLuJe" ]] ; then
		export KT_NO_USERATHOST_TAG="true"
		export CFLAGS="-march=i686 -pipe -O2 -fomit-frame-pointer -DKT_USERATHOST='\"NiLuJe@Ajulutsikael\"'"
	fi
	cd KindleTool/KindleTool
	# Disable dynamic libraries...
	mv -v /usr/lib/libarchive.dll.a{,.disabled}
	mv -v /usr/bin/cygarchive-14.dll{,.disabled}
	make clean
	make strip
	## Restore dynamic libraries...
	mv -v /usr/lib/libarchive.dll.a{.disabled,}
	mv -v /usr/bin/cygarchive-14.dll{.disabled,}

	# Package it
	git log --stat --graph > ../../ChangeLog
	./version.sh PMS
	VER_FILE="VERSION"
	VER_CURRENT="$(<${VER_FILE})"
	# Strip the git commit
	REV="${VER_CURRENT%%-*}"
	#REV="${VER_CURRENT}"
	cd ../..
	cp -v KindleTool/KindleTool/Release/kindletool.exe ./kindletool.exe
	cp -v KindleTool/README.md ./README
	# Quick! Markdown => plaintext
	sed -si 's/<b>//g;s/<\/b>//g;s/<i>//g;s/<\/i>//g;s/&lt;/</g;s/&gt;/>/g;s/&amp;/&/g;s/^* /  /g;s/*//g;s/>> /\t/g;s/^> /  /g;s/^## //g;s/### //g;s/\t/    /g;s/^\([[:digit:]]\)\./  \1)/g;s/^#.*$//;s/[[:blank:]]*$//g' README
	mv -v KindleTool/KindleTool/VERSION ./VERSION
	# LF => CRLF...
	unix2dos CREDITS README ChangeLog
	7z a -tzip kindletool-${REV}-cygwin.zip kindletool.exe CREDITS README ChangeLog VERSION
	rm -f kindletool.exe CREDITS README ChangeLog VERSION
}

# OS X !
Build_OSX() {
	echo "* Preparing a static KindleTool build on OS X . . ."
	# Make sure it'll run on OS X 10.6, too
	export MACOSX_DEPLOYMENT_TARGET=10.6
	export CFLAGS="-march=core2 -pipe -O2 -fomit-frame-pointer -mmacosx-version-min=10.6"
	export CXXFLAGS="-march=core2 -pipe -O2 -fomit-frame-pointer -mmacosx-version-min=10.6"
	export LDFLAGS=""

	LIBARCHIVE_VER="3.1.2"
	LIBARCHIVE_DIR="libarchive-${LIBARCHIVE_VER}"

	# Make sure we're up to date
	git pull

	# Get out of our git tree
	cd ../..

	# libarchive
	if [[ ! -d "${LIBARCHIVE_DIR}" ]] ; then
		echo "* Building ${LIBARCHIVE_DIR} . . ."
		echo ""
		if [[ ! -f "./${LIBARCHIVE_DIR}.tar.gz" ]] ; then
			curl -L "http://github.com/libarchive/libarchive/archive/v${LIBARCHIVE_VER}.tar.gz" -o "./${LIBARCHIVE_DIR}.tar.gz"
		fi
		tar -xvzf ./${LIBARCHIVE_DIR}.tar.gz
		cd ${LIBARCHIVE_DIR}
		./build/autogen.sh
		./configure --prefix=/opt/local --enable-static --enable-shared --disable-xattr --disable-acl --with-zlib --without-bz2lib --without-lzmadec --without-iconv --without-lzma --without-nettle --without-expat --without-xml2 --without-openssl
		make
		cd ..
	fi

	# Build KT package credits
	mkdir -p Release
	cat > Release/CREDITS << EOF
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
	# Fake user@host tag
	if echo "$(whoami)" | grep -E -e '^[nNiIlLuUjJeE]{6}' > /dev/null 2>&1 ; then
		export KT_NO_USERATHOST_TAG="true"
		export CFLAGS="-march=core2 -pipe -O2 -fomit-frame-pointer -mmacosx-version-min=10.6 -DKT_USERATHOST='\"niluje@ajulutsikael\"'"
	fi
	export CPPFLAGS="-Iincludes"
	export LDFLAGS="-Llib"
	cd KindleTool/KindleTool
	rm -rf lib includes
	mkdir -p lib includes
	cp -v ../../${LIBARCHIVE_DIR}/.libs/libarchive.a lib
	cp -v ../../${LIBARCHIVE_DIR}/libarchive/archive.h includes
	cp -v ../../${LIBARCHIVE_DIR}/libarchive/archive_entry.h includes
	make clean
	make strip
	rm -rf lib includes

	# Package it
	git log --stat --graph > ../../Release/ChangeLog
	./version.sh PMS
	VER_FILE="VERSION"
	VER_CURRENT="$(<${VER_FILE})"
	# Strip the git commit
	REV="${VER_CURRENT%%-*}"
	#REV="${VER_CURRENT}"
	cd ../..
	cd Release
	cp -v ../KindleTool/KindleTool/Release/kindletool ./kindletool
	cp -v ../KindleTool/README.md ./README
	# Quick! Markdown => plaintext
	perl -pi -e 's/<b>//g;s/<\/b>//g;s/<i>//g;s/<\/i>//g;s/&lt;/</g;s/&gt;/>/g;s/&amp;/&/g;s/^\* /  /g;s/\*//g;s/>> /\t/g;s/^> /  /g;s/^## //g;s/### //g;s/\t/    /g;s/^([[:digit:]])\./  \1)/g;s/^#.*$//;s/[[:blank:]]*$//g' ./README
	cp -v ../KindleTool/KindleTool/kindletool.1 ./kindletool.1
	mv -v ../KindleTool/KindleTool/VERSION ./VERSION
	rm -f kindletool-${REV}-osx.zip
	# Don't store uid/gid & attr, I'm packaging this on a 3rd party's computer
	zip -X kindletool-${REV}-osx.zip kindletool CREDITS README kindletool.1 ChangeLog VERSION
	rm -f kindletool CREDITS README kindletool.1 ChangeLog VERSION
	cd ..

	## NOTE: Do we need to do a MacPorts build? (link against MacPorts libs, instead of OS X's OpenSSL 0.9.8/zlib 1.2.5?
}

# Main
case "${OSTYPE}" in
	"Linux" )
		Build_Linux
	;;
	CYGWIN* )
		## NOTE: Output from uname -s is uppercase and appends info about the host's Windows version (ie. CYGWIN_NT-6.1), while uname -o will simply report Cygwin
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
