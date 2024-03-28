obj-m += hypercall.o

PWD := $(CURDIR)

all: hypercall.ko leak

leak: leak.c
	$(CC) -no-pie $^ -o $@

hypercall.ko: hypercall.c hypercall.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf *.o leak
