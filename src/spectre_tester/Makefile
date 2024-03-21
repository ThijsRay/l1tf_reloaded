obj-m += spectre_scanner_host.o

PWD := $(CURDIR)

all: spectre_tester_guest
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

spectre_tester_guest: spectre_tester_guest.o

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf spectre_tester_guest spectre_tester_guest.o
