include config.mk

.PHONY: clean

CFLAGS += -D_BSD_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE=2 -D__USE_MINGW_ANSI_STDIO=1

all: nustool

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

nustool: crypto.o main.o download.o util.o
	$(CC) -o $@ $^ $(LDFLAGS)

crypto.o: crypto.h types.h

main.o: main.c download.h types.h util.h

download.c: download.h types.h util.h

util.o: util.c util.h types.h version.h

clean:
	rm -f *.o nustool nustool.exe

dist:
	$(eval NUSTOOLVER = $(shell grep '\bNUSTOOL_VERSION\b' version.h \
		| cut -d'	' -f2 \
		| sed -e 's/"//g'))
	mkdir nustool-$(NUSTOOLVER)
	cp *.c *.h config.mk Makefile README.md LICENSE nustool-$(NUSTOOLVER)
	tar czf nustool-$(NUSTOOLVER).tar.gz nustool-$(NUSTOOLVER)
	rm -r nustool-$(NUSTOOLVER)

