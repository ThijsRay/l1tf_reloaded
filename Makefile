.PHONY: build
build: CMakeLists.txt
	mkdir -p build && cd build && cmake ..

.PHONY: clean
clean:
	$(MAKE) -C build clean
	rm -rf build

%: build
	$(MAKE) -C build

.PHONY: modules
modules: pteditor.ko
	$(MAKE) -C src/modules

.PHONY: insert_modules
insert_modules: modules pteditor.ko
	insmod $(SRC_DIR)/modules/hypercall/hypercall.ko
	insmod $(PTEDIT_DIR)/module/pteditor.ko

.PHONY: remove_modules
remove_modules:
	rmmod hypercall
	rmmod pteditor
