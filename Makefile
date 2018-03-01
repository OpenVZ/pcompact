include Makefile.incl

PCOMPACT = pcompact
MANDIR ?= /usr/share/man
SBINDIR ?= /usr/sbin
SYSCONFDIR ?= /etc
VERSION=$(shell cat Makefile.version)
DOCDIR ?= /usr/share/doc/$(PCOMPACT)-$(VERSION)

CFLAGS=-Wall -Wno-pointer-sign -Werror
LDFLAGS+=-lvzctl2 -lploop -lyajl -lrt -luuid
OBJS = main.o parser.o

define do_rebrand
	sed -e "s,@PRODUCT_NAME_SHORT@,$(PRODUCT_NAME_SHORT),g" -i $(1) || exit 1;
endef

all: $(PCOMPACT)

$(PCOMPACT): ${OBJS}
	$(CC) $(LDFLAGS) $^ -o $@

parser: parser.c
	$(CC) $(LDFLAGS) $(CFLAGS) -DMAIN parser.c -o parser

install: $(PCOMPACT)
	for mandir in 5 8; do \
		mkdir -p $(DESTDIR)$(MANDIR)/man$$mandir; \
	done
	mkdir -p $(DESTDIR)$(SBINDIR)
	for sysconfd in cron.d vz; do \
		mkdir -p $(DESTDIR)$(SYSCONFDIR)/$$sysconfd; \
	done
	install -m 755 $(PCOMPACT) $(DESTDIR)$(SBINDIR)/$(PCOMPACT)
	install -m 644 $(PCOMPACT).conf.5 $(DESTDIR)$(MANDIR)/man5/$(PCOMPACT).conf.5
	$(call do_rebrand,$(DESTDIR)$(MANDIR)/man5/$(PCOMPACT).conf.5)
	install -m 644 $(PCOMPACT).8 $(DESTDIR)$(MANDIR)/man8/$(PCOMPACT).8
	$(call do_rebrand,$(DESTDIR)$(MANDIR)/man8/$(PCOMPACT).8)
	install -m 644 etc/cron.d/$(PCOMPACT) $(DESTDIR)$(SYSCONFDIR)/cron.d/$(PCOMPACT)
	install -m 644 etc/$(PCOMPACT).conf $(DESTDIR)$(SYSCONFDIR)/vz/$(PCOMPACT).conf

install-licenses:
	mkdir -p $(DESTDIR)$(DOCDIR)
	for l in GPL-2.0 COPYING; do \
		install -m 644 $$l $(DESTDIR)$(DOCDIR); \
	done

clean:
	rm -f $(PCOMPACT) parser ${OBJS}
