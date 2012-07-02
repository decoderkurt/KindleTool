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