CC?=gcc
STRIP?=strip
DEBUG_CFLAGS=-O0 -march=native -fno-omit-frame-pointer -pipe -g3
# FIXME: For debug builds, start using -Og instead of -O0 ASAP (GCC 4.8 only, IIRC)
OPT_CFLAGS=-O2 -march=native -fomit-frame-pointer -pipe
K3_CFLAGS=-O2 -ffast-math -march=armv6j -mtune=arm1136jf-s -fomit-frame-pointer -pipe -fno-stack-protector -U_FORTIFY_SOURCE
MINGW_CFLAGS=-O2 -ffast-math -march=i686 -mtune=i686 -fomit-frame-pointer -pipe
# When we want to use clang's asan (http://clang.llvm.org/docs/AddressSanitizer.html), because it rocks.
ASAN_CLFAGS="-O1 -march=native -fno-omit-frame-pointer -pipe -fno-optimize-sibling-calls -Weverything -Wno-disabled-macro-expansion -fsanitize=address -g3"
# In the same vein, since valgrind 2.8.0 now runs properly on my Gentoo system, here's a few notes about its current report:
# (Using --leak-check=full --track-origins=yes --show-reachable=yes)
# The getpwuid_r/getgrgid_r thing from libarchive's archive_read_disk_set_standard_lookup is mostly harmless (cf. http://sourceware.org/bugzilla/show_bug.cgi?id=2314),
# and only happens when using the NSS compat stuff (which happened to be the default on my system...)
# Same thing for OpenSSL's uninitialized stuff when built without PURIFY (cf. OpenSSL's FAQ)

# Kindle cross toolchain prefix
ifeq "$(KINDLE)" "true"
	CROSS_PREFIX?=arm-kindle-linux-gnueabi-
endif
# MinGW cross toolchain prefix
ifeq "$(MINGW)" "true"
	CROSS_PREFIX?=i686-w64-mingw32-
endif

SRCS=kindle_tool.c create.c convert.c

default: all

# OS, version, pkgconfig & misc stuff handling (heavily inspired from git's Makefiles ;))
# It's basically our fake automated configure script, and it uses bash features, so override the default shell!
SHELL:=/bin/bash
version-inc:
	@$(SHELL) ./version.sh
-include version-inc

# Try to use sane defaults for DESTDIR/PREFIX, while still playing nice with PMS
ifndef DESTDIR
	PREFIX:=/.
else
	ifeq "$(OSTYPE)" "Darwin"
		# Play nice with MacPorts
		PREFIX:=/opt/local
	else
		# Should play nice with various Linux PMS, specifically non-prefixed Portage/Paludis setups
		PREFIX:=/usr
	endif
endif
ifeq "$(OSTYPE)" "Darwin"
	DESTDIR?=/opt/local
else
	DESTDIR?=/usr/local
endif
BINDIR:=$(DESTDIR)/$(PREFIX)/bin
MANDIR:=$(DESTDIR)/$(PREFIX)/share/man/man1

ifeq "$(OSTYPE)" "Darwin"
	CPPFLAGS?=-I/opt/local/include
else
	CPPFLAGS?=-Iincludes
endif

# We of course need libarchive
LIBS=-larchive
# Do we want to force OpenSSL?
ifdef KT_FORCE_NO_NETTLE
	# Quick shortcut, overwrite the pc test, so we don't have to be more messy in the conditionals later on...
	HAS_PC_NETTLE:="false"
endif
# Do we have nettle? If so, use it!
ifeq "$(HAS_PC_NETTLE)" "true"
	LIBS+=$(PC_NETTLE_LIBS)
else
	# Fall back to OpenSSL
	LIBS+=-lcrypto
	# Needed for linking statically against OpenSSL on Linux, and as as-needed takes care of it when building dynamically, it doesn't hurt to keep it set in both cases ;).
	ifeq "$(OSTYPE)" "Linux"
		# There's no libdl on Windows ;)
		ifneq "$(MINGW)" "true"
			LIBS+=-ldl
		endif
	endif
	# Needed for linking statically against OpenSSL on MinGW
	ifeq "$(MINGW)" "true"
		LIBS+=-lgdi32
	endif
endif
# And we'll always need zlib, at least for libarchive, possibly for OpenSSL
LIBS+=-lz

# If we want to use part of gperftools (http://gperftools.googlecode.com/svn/trunk/doc/heap_checker.html for example)
#ifeq "$(OSTYPE)" "Linux"
#	LIBS+=-ltcmalloc
#endif

ifeq "$(DEBUG)" "true"
	OUT_DIR=Debug
	CFLAGS:=$(DEBUG_CFLAGS)
else
	OUT_DIR=Release
	CFLAGS?=$(OPT_CFLAGS)
endif

ifeq "$(KINDLE)" "true"
	OUT_DIR=Kindle
	CFLAGS?=$(K3_CFLAGS)
	CC:=$(CROSS_PREFIX)gcc
	STRIP:=$(CROSS_PREFIX)strip
endif

ifeq "$(MINGW)" "true"
	OUT_DIR=MinGW
	CFLAGS?=$(MINGW_CFLAGS)
	CC:=$(CROSS_PREFIX)gcc
	STRIP:=$(CROSS_PREFIX)strip
endif

# Oh, OS X...
ifeq "$(OSTYPE)" "Darwin"
	STRIP_OPTS:=
else
	STRIP_OPTS:=--strip-unneeded
endif

# It appears that Windows is using a strange & incongruous file extension for its binaries... ;D
ifeq "$(MINGW)" "true"
	# Cygwin is smart enough to take care of it itself, so just check MinGW ;)
	BINEXT:=.exe
else
	BINEXT:=
endif

# NOTE: All the KT_ prefixed *FLAGS are stuff that we *always* want set, no matter what the user does.
# Moar warnings!
KT_CFLAGS+=-Wall -Wformat -Wformat-security
KT_CFLAGS+=-Wextra -Wunused
KT_CFLAGS+=-Wshadow
KT_CFLAGS+=-Wmissing-prototypes
KT_CFLAGS+=-Wcast-qual
KT_CFLAGS+=-Wconversion
# libarchive is always built with large files support, do the same to avoid issues.
KT_CPPFLAGS+=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
# Get a printf function family with GNU extensions support on MinGW...
ifeq "$(MINGW)" "true"
	# That's enough for MinGW
	KT_CPPFLAGS+=-D_GNU_SOURCE
	# But not for MinGW-w64...
	KT_CPPFLAGS+=-D__USE_MINGW_ANSI_STDIO=1
endif
KT_CPPFLAGS+=-DKT_VERSION='"$(KT_VERSION)"'
# Add a user@host build tag, unless explicitly forbidden
ifndef KT_NO_USERATHOST_TAG
	KT_CPPFLAGS+=-DKT_USERATHOST='"$(COMPILE_BY)@$(COMPILE_HOST)"'
endif
# Play with valid unknown device codes in debug builds...
ifeq "$(DEBUG)" "true"
	KT_CPPFLAGS+=-DKT_UNKNOWN_DEVID
endif
# If we have nettle, use it
ifeq "$(HAS_PC_NETTLE)" "true"
	KT_CPPFLAGS+=-DKT_USE_NETTLE
	# Also pass out stupid hack to get the buildtime nettle version...
	KT_CPPFLAGS+=-DNETTLE_VERSION='"$(PC_NETTLE_VERSION)"'
endif

ifndef LDFLAGS
	ifeq "$(OSTYPE)" "Darwin"
		LDFLAGS:=-L/opt/local/lib
	else
		LDFLAGS:=-Llib
		LDFLAGS+=-Wl,-O1 -Wl,--as-needed
	endif
endif

# If we're on Linux, not on Gentoo, and pkgconfig detected libarchive >= 3.0.3, use its CPP/LDFLAGS for include & lib searchpath
# That should help us link against the correct libarchive version on Debian/Ubuntu, where libarchive-2 and libarchive-3 coexist with a single -dev package
ifeq "$(OSTYPE)" "Linux"
	ifneq "$(DISTRIB_ID)" "Gentoo"
		ifeq "$(HAS_PC_LIBARCHIVE)" "true"
			CPPFLAGS+=$(PC_LIBARCHIVE_CPPFLAGS)
			LDFLAGS+=$(PC_LIBARCHIVE_LDFLAGS)
		endif
		# Do the same for nettle
		ifeq "$(HAS_PC_NETTLE)" "true"
			CPPFLAGS+=$(PC_NETTLE_CPPFLAGS)
			LDFLAGS+=$(PC_NETTLE_LDFLAGS)
		endif
	endif
endif

# Let's say we want to default to building stuff that will work on OS X 10.6/10.7... If I get how this stuff works, that should do it...
#ifeq "$(OSTYPE)" "Darwin"
#	# Check that we don't mess with MacPorts, which defaults to the OS version... (I'm not sure MacPorts even sets it for us, since we're not using autotools...)
#	# Although it supposedly defaults to the OS version since OS X 10.5 anyway, so...
#	ifndef MACOSX_DEPLOYMENT_TARGET
#		export MACOSX_DEPLOYMENT_TARGET=10.6
#		KT_CFLAGS+=-mmacosx-version-min=10.6
#	endif
#endif

OBJS:=$(SRCS:%.c=$(OUT_DIR)/%.o)

$(OUT_DIR)/%.o: %.c
	$(CC) $(CPPFLAGS) $(KT_CPPFLAGS) $(CFLAGS) $(KT_CFLAGS) -o $@ -c $<

outdir:
	mkdir -p $(OUT_DIR)

all: outdir kindletool

kindletool: version-inc $(OBJS)
	$(CC) $(CPPFLAGS) $(KT_CPPFLAGS) $(CFLAGS) $(KT_CFLAGS) $(LDFLAGS) -o$(OUT_DIR)/$@$(BINEXT) $(OBJS) $(LIBS)

strip: all
	$(STRIP) $(STRIP_OPTS) $(OUT_DIR)/kindletool$(BINEXT)

debug:
	$(MAKE) all DEBUG=true

kindle:
	$(MAKE) strip KINDLE=true

mingw:
	$(MAKE) strip MINGW=true

clean:
	rm -rf Release/*.o
	rm -rf Release/kindletool
	rm -rf Debug/*.o
	rm -rf Debug/kindletool
	rm -rf Kindle/*.o
	rm -rf Kindle/kindletool
	rm -rf MinGW/*.o
	rm -rf MinGW/kindletool.exe
	rm -rf version-inc

install: all
	install -d -m 755 $(BINDIR)
	install '$(OUT_DIR)/kindletool' $(BINDIR)
	install -d -m 755 $(MANDIR)
	install -m 644 kindletool.1 $(MANDIR)


.PHONY: all install clean default outdir kindletool strip debug kindle mingw
