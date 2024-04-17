PROGRAMS = l1tf half_spectre_leak

l1tf_OBJS = l1tf.o flush_and_reload.o statistics.o

half_spectre_leak_OBJS = half_spectre_leak.o time_deque.o

############

INC_DIR = include
SRC_DIR = src
OBJ_DIR = obj

CFLAGS += -Wall -Wextra -I$(INC_DIR) -g -O0
LDFLAGS += -lm -no-pie

SRC_FILES = $(wildcard src/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)%.c,$(OBJ_DIR)%.o,$(SRC_FILES))
INC_FILES = $(wildcard ($INC_DIR)/*.h)

.PHONY: all
all: $(PROGRAMS) hypercall

# Adapted from https://www.gnu.org/software/make/manual/html_node/Eval-Function.html
define PROGRAM_template =
 $(1): $(addprefix $(OBJ_DIR)/, $($(1)_OBJS))
 ALL_OBJS   += $(addprefix $(OBJ_DIR)/, $($(1)_OBJS))
endef

$(foreach prog,$(PROGRAMS),$(eval $(call PROGRAM_template,$(prog))))

$(PROGRAMS):
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(ALL_OBJS): $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_FILES) Makefile
	@mkdir -p $(OBJ_DIR)
	$(CC) -c $(CFLAGS) $(filter %.c,$^) -o $@

.PHONY: clean
clean:
	$(RM) -r obj $(PROGRAMS)
	$(MAKE) -C $(SRC_DIR)/hypercall clean

.PHONY: hypercall
hypercall:
	$(MAKE) -C $(SRC_DIR)/hypercall

print-%: ; @echo $*=$($*)
