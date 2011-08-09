LDFLAGS=-static
PROGS=mknod mount ifconfig udhcpc sh

all: virtunoid initrd.gz

virtunoid: virtunoid-config.h

initrd: out/virtunoid out/init out/proc $(PROGS:%=out/bin/%)
	(cd out && find | cpio -o -Hnewc) > $@

%.gz: %
	gzip -f $<

out out/bin out/proc: %: $(dirname %)
	mkdir -p $@

$(PROGS:%=out/bin/%): out/bin/%: out/bin/busybox
	ln -sf busybox $@

out/bin/busybox: out out/bin
	cp /bin/busybox $@

out/init out/virtunoid: out/%: % out
	cp $< $@

