obj-m += memory_watchdog.o
EXTRA_CFLAGS += -mfunction-return=keep -mindirect-branch=keep

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
