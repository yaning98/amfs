ifneq ($(KERNELRELEASE),)
include Kbuild

else
KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
endif

