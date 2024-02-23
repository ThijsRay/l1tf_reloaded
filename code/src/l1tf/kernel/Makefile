obj-m += l1tf.o

PWD := $(CURDIR)

kernel_l1tf.o:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
