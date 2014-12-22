prefix=/usr
bin=$(prefix)/bin

CFLAGS=-O1

all:
	$(CC) -c pmkdump.c -o pmkdump.o -g $(CFLAGS)
	$(CC) pmkdump.o -lcrypto -lpcap -lpthread -o pmkdump -g

install:
	install -m 755 -o root -g root pmkdump $(bin)

uninstall:
	rm -f $(bin)/pmkdump

clean:
	rm -f pmkdump *.o *~

