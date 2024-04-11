INC_DIR = $(PWD)/../../include
obj-m += hypercall.o

ccflags-y += -I$(INC_DIR)

PWD := $(CURDIR)

all: hypercall.ko kvm_assist/kvm_assist.ko

kvm_assist/kvm_assist.ko: kvm_assist/kvm_assist.c
	$(MAKE) -C kvm_assist

hypercall.ko: hypercall.c $(INC_DIR)/hypercall.h
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	$(MAKE) -C kvm_assist clean
