#!/bin/bash
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
	export CFLAGS="-pipe -O2 -fomit-frame-pointer -march=native"
	export CFLAGS="-pipe -O2 -fomit-frame-pointer -march=native"
	export LDFLAGS="-Wl,-O1 -Wl,--as-needed"

	LIBARCHIVE_DIR="libarchive-3.0.4"

	# Make sure we're up to date
	git pull

	# Get out of our git tree
	cd ../..

	# libarchive
	if [[ ! -d "${LIBARCHIVE_DIR}" ]] ; then
		echo "* Building ${LIBARCHIVE_DIR} . . ."
		echo ""
		export ac_cv_header_ext2fs_ext2_fs_h=0
		if [[ ! -f "./${LIBARCHIVE_DIR}.tar.gz" ]] ; then
			wget -O "./${LIBARCHIVE_DIR}.tar.gz" "https://github.com/downloads/libarchive/libarchive/${LIBARCHIVE_DIR}.tar.gz"
		fi
		tar -xvzf ./${LIBARCHIVE_DIR}.tar.gz
		cd ${LIBARCHIVE_DIR}
		./configure --enable-static --disable-shared --disable-xattr --disable-acl --with-zlib --without-bz2lib --without-lzmadec --without-iconv --without-lzma --without-nettle --without-expat --without-xml2 --without-openssl
		make
		unset ac_cv_header_ext2fs_ext2_fs_h
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

	# KindleTool
	echo "* Building KindleTool . . ."
	echo ""
	export LDFLAGS="-Llib -Wl,-O1 -Wl,--as-needed"
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
	git log --stat --graph > ../../ChangeLog
	./version.sh PMS
	VER_FILE="VERSION"
	VER_CURRENT="$(<${VER_FILE})"
	# Strips the git commit
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
