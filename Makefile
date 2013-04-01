CONFIG_WIFI_STATISTICS=m

PWD:=$(shell pwd)
KERNELPATH ?= /lib/modules/$(shell uname -r)/build
export KERNELPATH
ifeq ($(shell cd $(KERNELPATH) && pwd),)
	$(warning $(KERNELPATH) is missing, please set KERNELPATH)
endif

export KERNELPATH
include $(PWD)/Makefile.kbuild


all:
	$(MAKE) -C $(KERNELPATH) M=$(PWD) PWD=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELPATH) M=$(PWD) PWD=$(PWD) clean

.PHONY:	all clean
