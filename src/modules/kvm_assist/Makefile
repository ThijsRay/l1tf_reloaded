INC_DIR = $(PWD)/../../../include
obj-m += kvm_assist.o

ccflags-y += -I$(INC_DIR)

PWD := $(CURDIR)

kvm_assist.ko: kvm_assist.c $(INC_DIR)/hypercall.h
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
