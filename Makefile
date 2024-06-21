.PHONY: build
build: CMakeLists.txt
	mkdir -p build && cd build && cmake ..

.PHONY: clean
clean:
	$(MAKE) -C build clean
	$(MAKE) -C src/modules clean
	rm -rf build

.PHONY: modules
modules: pteditor.ko
	$(MAKE) -C src/modules

.PHONY: insert_modules
insert_modules: modules pteditor.ko
	insmod src/modules/hypercall/hypercall.ko
	insmod deps/PTEditor/module/pteditor.ko

.PHONY: remove_modules
remove_modules:
	rmmod hypercall
	rmmod pteditor

%:
	$(MAKE) -C build $@
