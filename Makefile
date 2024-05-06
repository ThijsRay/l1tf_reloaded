PROGRAMS = l1tf kvm_leak cache_eviction

l1tf_OBJS = l1tf.o flush_and_reload.o statistics.o

kvm_leak_OBJS = kvm_leak.o time_deque.o

cache_eviction_OBJS = cache_eviction.o

############

INC_DIR = include
SRC_DIR = src
OBJ_DIR = obj

CFLAGS += -Wall -Wextra -I$(INC_DIR) -g -O0
LDFLAGS += -Wl,-rpath,$(PWD)/deps/evsets -Ldeps/evsets -lm -levsets -no-pie

SRC_FILES = $(wildcard src/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)%.c,$(OBJ_DIR)%.o,$(SRC_FILES))
INC_FILES = $(wildcard $(INC_DIR)/*.h)

PTEDIT_DIR = deps/PTEditor
EVSETS_DIR = deps/evsets

.PHONY: all
all: modules $(PROGRAMS)

$(INC_DIR)/ptedit_header.h: $(PTEDIT_DIR)
	$(MAKE) -C $(PTEDIT_DIR) header
	ln -sf ../$(PTEDIT_DIR)/ptedit_header.h $(INC_DIR)/ptedit_header.h

INC_FILES += $(INC_DIR)/ptedit_header.h

$(INC_DIR)/evsets_api.h $(INC_DIR)/public_structs.h: $(EVSETS_DIR)
	$(MAKE) -C $(EVSETS_DIR) libevsets.so
	mkdir -p $(INC_DIR)/evsets
	ln -sf ../../$(EVSETS_DIR)/evsets_api.h $(INC_DIR)/evsets/evsets_api.h
	ln -sf ../../$(EVSETS_DIR)/public_structs.h $(INC_DIR)/evsets/public_structs.h

INC_FILES += $(INC_DIR)/evsets_api.h $(INC_DIR)/public_structs.h

# Adapted from https://www.gnu.org/software/make/manual/html_node/Eval-Function.html
define PROGRAM_template =
 $(1): $(addprefix $(OBJ_DIR)/, $($(1)_OBJS))
 ALL_OBJS   += $(addprefix $(OBJ_DIR)/, $($(1)_OBJS))
endef

$(foreach prog,$(PROGRAMS),$(eval $(call PROGRAM_template,$(prog))))

$(PROGRAMS):
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@ $(LDFLAGS)

$(ALL_OBJS): $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_FILES) Makefile
	@mkdir -p $(OBJ_DIR)
	$(CC) -c $(CFLAGS) $(filter %.c,$^) -o $@

.PHONY: clean
clean:
	$(RM) -r obj $(PROGRAMS) $(INC_DIR)/ptedit_header.h
	$(MAKE) -C $(SRC_DIR)/modules clean
	$(MAKE) -C $(PTEDIT_DIR) clean
	$(MAKE) -C $(EVSETS_DIR) clean

.PHONY: modules
modules:
	$(MAKE) -C $(SRC_DIR)/modules
	$(MAKE) -C $(PTEDIT_DIR) pteditor

.PHONY: insert_modules
insert_modules: modules
	insmod $(SRC_DIR)/modules/hypercall/hypercall.ko
	insmod $(PTEDIT_DIR)/module/pteditor.ko

.PHONY: remove_modules
remove_modules:
	rmmod hypercall
	rmmod pteditor

print-%: ; @echo $*=$($*)
