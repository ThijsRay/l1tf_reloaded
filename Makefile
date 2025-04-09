.PHONY: run_exploit
run_exploit:
	make exploit
	./build/exploit 2>>std.err | tee -a std.out

all: build
	$(MAKE) kvm_leak
	$(MAKE) victim
	$(MAKE) hypercall
	$(MAKE) kvm_assist
	$(MAKE) pteditor.ko

.PHONY: load_modules
load_modules: hypercall pteditor.ko
	sudo insmod deps/PTEditor/module/pteditor.ko
	sudo insmod build/hypercall/hypercall.ko

.PHONY: unload_modules
unload_modules:
	sudo rmmod pteditor
	sudo rmmod hypercall

.PHONY: load_kvm_assist
load_kvm_assist: kvm_assist
	sudo insmod build/kvm_assist/kvm_assist.ko

.PHONY: unload_kvm_assist
unload_kvm_assist:
	sudo rmmod kvm_assist

deps/PTEditor/ptedit_header.h:
	git submodule update --init --recursive

build: CMakeLists.txt deps/PTEditor/ptedit_header.h
	mkdir -p build && cd build && cmake ..

.PHONY: clean
clean:
	$(RM) -r build

%: build
	$(MAKE) -C build $@
