MODULES = kvm_assist hypercall
.DEFAULT_GOAL += all

define MODULE_make =
$(1)/$(1).ko: $(1)/$(1).c
	$(MAKE) -C ./$(1)

MAKE_TARGETS += $(1)/$(1).ko
endef
$(foreach module,$(MODULES),$(eval $(call MODULE_make,$(module))))

all: $(MAKE_TARGETS)

define MODULE_clean =
.PHONY: $(1)_CLEAN
$(1)_CLEAN:
	$(MAKE) -C ./$(1) clean

CLEAN_TARGETS += $(1)_CLEAN
endef
$(foreach module,$(MODULES),$(eval $(call MODULE_clean,$(module))))

.PHONY: clean
clean: $(CLEAN_TARGETS)

define MODULE_insert =
.PHONY: $(1)_INSERT
$(1)_INSERT: $(1)
	insmod $(1)
INSERT_TARGETS += $(1)_INSERT
endef
$(foreach target,$(MAKE_TARGETS),$(eval $(call MODULE_insert,$(target))))

.PHONY: insert
insert: $(INSERT_TARGETS)




