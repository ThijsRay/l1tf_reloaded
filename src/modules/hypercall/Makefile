INC_DIR = $(PWD)/../../../include
obj-m += hypercall.o

ccflags-y += -I$(INC_DIR)

PWD := $(CURDIR)

hypercall.ko: hypercall.c $(INC_DIR)/hypercall.h
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
