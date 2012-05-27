CC?=gcc
STRIP?=strip
DEBUG_CFLAGS=-O0 -ggdb3 -march=native
OPT_CFLAGS=-O2 -fomit-frame-pointer -march=native
K3_CFLAGS=-O2 -ffast-math -march=armv6j -mtune=arm1136jf-s -fomit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE

# Kindle cross toolchain prefix
CROSS_PREFIX?=arm-kindle-linux-gnueabi-

SRCS=kindle_tool.c create.c convert.c

default: all

# OS & Version handling (taken from the git makefiles)
SHELL:=/bin/bash
version-inc:
	@$(SHELL) ./version.sh `$(CC) -dumpversion`
-include version-inc

ifndef DESTDIR
	PREFIX:=/.
else
	PREFIX:=/usr
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
LIBS=-lcrypto -larchive

ifeq "$(DEBUG)" "true"
	OUT_DIR=Debug
	CFLAGS:=$(DEBUG_CFLAGS)
else
	OUT_DIR=Release
	CFLAGS?=$(OPT_CFLAGS)
endif

ifeq "$(KINDLE)" "true"
	OUT_DIR=Kindle
	CFLAGS:=$(K3_CFLAGS)
	LDFLAGS=-Wl,-O1 -Wl,--as-needed
	CC:=$(CROSS_PREFIX)gcc
	STRIP:=$(CROSS_PREFIX)strip
endif

CFLAGS+=-pipe
# Moar warnings!
CFLAGS+=-Wall -Wformat -Wformat-security
CFLAGS+=-Wextra -Wunused
CFLAGS+=-Wshadow
CFLAGS+=-Wmissing-prototypes
CFLAGS+=-Wcast-qual
# libarchive is always built with large files support, do the same to avoid issues.
CFLAGS+=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS+=-DKT_VERSION='"$(KT_VERSION)"'

ifndef LDFLAGS
	ifeq "$(OSTYPE)" "Darwin"
		LDFLAGS:=-L/opt/local/lib
	else
		LDFLAGS:=-Llib
		LDFLAGS+=-Wl,-O1 -Wl,--as-needed
	endif
endif

OBJS:=$(SRCS:%.c=$(OUT_DIR)/%.o)

$(OUT_DIR)/%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

outdir:
	mkdir -p $(OUT_DIR)

ifeq "$(OSTYPE)" "Linux"
kindletool.1:
	cp -af KindleTool.1 kindletool.1
else
kindletool.1:
endif

all: outdir kindletool kindletool.1

kindletool: version-inc $(OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(OBJS) $(LIBS) -o$(OUT_DIR)/$@

strip: all
	$(STRIP) -s $(OUT_DIR)/kindletool

debug:
	$(MAKE) all DEBUG=true

kindle:
	$(MAKE) strip KINDLE=true

ifeq "$(OSTYPE)" "Linux"
clean_man:
	rm -rf kindletool.1
else
clean_man:
endif

clean: clean_man
	rm -rf Release/*.o
	rm -rf Release/kindletool
	rm -rf Debug/*.o
	rm -rf Debug/kindletool
	rm -rf Kindle/*.o
	rm -rf Kindle/kindletool
	rm -rf version-inc

ifeq "$(OSTYPE)" "Linux"
install_man:
	install -d -m 755 $(MANDIR)
	install -m 644 kindletool.1 $(MANDIR)
else
install_man:
	install -d -m 755 $(MANDIR)
	install -m 644 KindleTool.1 $(MANDIR)
endif

install: all install_man
	install -d -m 755 $(BINDIR)
	install '$(OUT_DIR)/kindletool' $(BINDIR)
	install -d -m 755 $(MANDIR)
	install -m 644 kindletool.1 $(MANDIR)


.PHONY: all install install_man clean clean_man default outdir kindletool strip debug kindle
