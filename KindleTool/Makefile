CC?=gcc
LD?=gcc
CFLAGS?=-O0 -ggdb3 -march=native -Wall
LDFLAGS?=
INCLUDES=-Llib -Iincludes
LIBS=-lcrypto -ltar -lz
DEPS=kindle_tool.h
OBJ=kindle_tool.o create.o convert.o

%.o: %.c $(DEPS)
	$(CC) $(INCLUDES) -c -o $@ $< $(CFLAGS)

kindletool: $(OBJ)
	$(LD) -o $@ $^ $(LDFLAGS) $(INCLUDES) $(LIBS)

clean:
	rm -f *.o kindletool
