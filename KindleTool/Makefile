GCC?=gcc
STRIP?=strip
DEBUG_CFLAGS=-O0 -ggdb3 -march=native
OPT_CFLAGS=-O2 -fomit-frame-pointer -march=native

SRCS=kindle_tool.c create.c convert.c
INCLUDES=-Llib -Iincludes
LIBS=-lcrypto -larchive

ifeq "$(DEBUG)" "true"
	OUT_DIR=Debug
	CFLAGS=$(DEBUG_CFLAGS)
else
	OUT_DIR=Release
	CFLAGS=$(OPT_CFLAGS)
endif

# libarchive is always built with large files support, do the same to avoid issues.
CFLAGS+=-pipe -Wall -DFILE_OFFSET_BITS=64
LDFLAGS?=-Wl,-O1 -Wl,--as-needed

OBJS:=$(SRCS:%.c=$(OUT_DIR)/%.o)

$(OUT_DIR)/%.o: %.c
	$(GCC) $(INCLUDES) $(CFLAGS) -o $@ -c $<

all:
	mkdir -p $(OUT_DIR)
	$(MAKE) kindletool

kindletool: $(OBJS)
	$(GCC) $(INCLUDES) $(CFLAGS) $(LDFLAGS) $(OBJS) $(LIBS) -o$(OUT_DIR)/$@

strip:
	$(MAKE) all
	$(STRIP) -s $(OUT_DIR)/kindletool

debug:
	$(MAKE) all DEBUG=true

default: all

clean:
	rm -rf Release/*.o
	rm -rf Release/kindletool
	rm -rf Debug/*.o
	rm -rf Debug/kindletool
