MANDIR ?= /usr/share/man
SBINDIR ?= /usr/sbin
SYSCONFDIR ?= /etc

CFLAGS=-Wall -Wno-pointer-sign -Werror
LDFLAGS+=-lvzctl2 -lploop -lyajl -lrt
OBJS = main.o parser.o

all: pcompact

pcompact: ${OBJS}
	$(CC) $(LDFLAGS) $^ -o $@

parser: parser.c
	$(CC) $(LDFLAGS) $(CFLAGS) -DMAIN parser.c -o parser

install: pcompact
	mkdir -p $(DESTDIR)$(MANDIR)/man5
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	mkdir -p $(DESTDIR)$(SBINDIR)
	mkdir -p $(DESTDIR)$(SYSCONFDIR)/cron.d
	mkdir -p $(DESTDIR)$(SYSCONFDIR)/vz
	install -m 755 pcompact $(DESTDIR)$(SBINDIR)/pcompact
	install -m 644 pcompact.conf.5 $(DESTDIR)$(MANDIR)/man5/pcompact.conf.5
	install -m 644 pcompact.8 $(DESTDIR)$(MANDIR)/man8/pcompact.8
	install -m 644 etc/cron.d/pcompact $(DESTDIR)$(SYSCONFDIR)/cron.d/pcompact
	install -m 644 etc/pcompact.conf $(DESTDIR)$(SYSCONFDIR)/vz/pcompact.conf

clean:
	rm -f pcompact parser ${OBJS}
