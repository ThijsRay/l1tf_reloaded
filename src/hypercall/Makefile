obj-m += hypercall.o

PWD := $(CURDIR)

all: hypercall.ko leak kvm_assist/kvm_assist.ko

leak: leak.c
	$(CC) -no-pie $^ -o $@

kvm_assist/kvm_assist.ko: kvm_assist/kvm_assist.c
	$(MAKE) -C kvm_assist

hypercall.ko: hypercall.c hypercall.h
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	$(MAKE) -C kvm_assist clean
	$(RM) *.o leak
