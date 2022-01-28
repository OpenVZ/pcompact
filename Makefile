include Makefile.incl

PCOMPACT = pcompact
MANDIR ?= /usr/share/man
SBINDIR ?= /usr/sbin
SYSCONFDIR ?= /etc
VERSION=$(shell cat Makefile.version)
DOCDIR ?= /usr/share/doc/$(PCOMPACT)-$(VERSION)

CFLAGS=-Wall -Wno-pointer-sign -Werror -Wall -Wno-pointer-sign -Werror -O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fexceptions -fstack-protector-strong -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection 
LDFLAGS+=-lvzctl2 -lvzevent -lploop -lyajl -lrt -luuid -lpthread
OBJS = main.o parser.o

define do_rebrand
	sed -e "s,@PRODUCT_NAME_SHORT@,$(PRODUCT_NAME_SHORT),g" -i $(1) || exit 1;
endef

all: $(PCOMPACT)

$(PCOMPACT): ${OBJS}
	$(CC) $^ $(LDFLAGS) -o $@

parser: parser.c
	$(CC) $(CFLAGS) -DMAIN parser.c $(LDFLAGS) -o parser

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
