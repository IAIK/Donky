obj-m += sysfilter.o
ccflags-y += -Wno-unused-result
all: test sysfilter.ko

sysfilter.ko: sysfilter.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

test: test.c
	gcc test.c -o test

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f test

load: sysfilter.ko
	@if ( ! test -e /dev/sysfilter ); then sudo insmod sysfilter.ko; else echo "Module already loaded"; fi
	@if ( ! lsmod | grep sysfilter ); then echo "Unable to load module!"; exit 1; else echo "Module loaded"; fi

unload:
	@if ( test -e /dev/sysfilter ); then sudo rmmod sysfilter.ko; else echo "No module loaded"; fi
	@if ( lsmod | grep sysfilter ); then echo "Unable to unload module!"; exit 1; else echo "Module unloaded"; fi
