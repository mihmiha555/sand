# Makefile for Sand hypervisor
# if it is built as external (out-of-tree) kernel module

KDIR ?= /lib/modules/$(shell uname -r)/build

sand-module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

sandctl: sandctl.c sand.h
	gcc -o sandctl sandctl.c -static

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f sandctl
