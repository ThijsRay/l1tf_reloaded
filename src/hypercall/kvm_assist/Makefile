obj-m += kvm_assist.o

PWD := $(CURDIR)

kvm_assist.ko: kvm_assist.c ../hypercall.h
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
