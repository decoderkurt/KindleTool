CC?=gcc
STRIP?=strip
DEBUG_CFLAGS=-O0 -ggdb3 -march=native
OPT_CFLAGS=-O2 -fomit-frame-pointer -march=native
K3_CFLAGS=-O2 -ffast-math -march=armv6j -mtune=arm1136jf-s -fomit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE

# Kindle cross toolchain prefix
CROSS_PREFIX?=arm-kindle-linux-gnueabi-

SRCS=kindle_tool.c create.c convert.c

CPPFLAGS?=-Iincludes
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

default: all

# Version handling (taken from the git makefiles)
SHELL:=/bin/bash
version-inc: .FORCE
	@$(SHELL) ./version.sh `$(CC) -dumpversion`
-include version-inc

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
	LDFLAGS:=-Llib
	LDFLAGS+=-Wl,-O1 -Wl,--as-needed
endif

OBJS:=$(SRCS:%.c=$(OUT_DIR)/%.o)

$(OUT_DIR)/%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

outdir:
	mkdir -p $(OUT_DIR)

kindletool.1:
	cp -af KindleTool.1 kindletool.1

all: outdir kindletool kindletool.1

kindletool: version-inc $(OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(OBJS) $(LIBS) -o$(OUT_DIR)/$@

strip: all
	$(STRIP) -s $(OUT_DIR)/kindletool

debug:
	$(MAKE) all DEBUG=true

kindle:
	$(MAKE) strip KINDLE=true

clean:
	rm -rf Release/*.o
	rm -rf Release/kindletool
	rm -rf Debug/*.o
	rm -rf Debug/kindletool
	rm -rf Kindle/*.o
	rm -rf Kindle/kindletool
	rm -rf version-inc
	rm -rf kindletool.1

.PHONY: all clean default outdir kindletool strip debug kindle
.PHONY: .FORCE
