# Makefile – makefile of our first driver
 
# if KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq (${KERNELRELEASE},)
	obj-m := hook.o
# Otherwise we were called directly from the command line.
# Invoke the kernel build system.
else
	KERNEL_SOURCE := /usr/src/linux-lts-trusty-3.13.0
	PWD := $(shell pwd)
	CFLAGS       += -fPIC -pedantic -Wall -Wextra -ggdb3
	LDFLAGS      += -shared
	ccflags-y := -fPIC --static
	LDFLAGS_MODULE += -static -fPIC
default:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} modules
 
clean:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} clean
endif
