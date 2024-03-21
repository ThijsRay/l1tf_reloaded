INC_DIR = include
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

CFLAGS += -Wall -Wextra -I$(INC_DIR) -g -ftrapv -z noexecstack -O0
LDFLAGS += -lm -no-pie

SRC_FILES = $(wildcard src/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)%.c,$(OBJ_DIR)%.o,$(SRC_FILES))
INC_FILES = $(wildcard include/*.h)

.PHONY: l1tf
l1tf: $(BIN_DIR)/l1tf
$(BIN_DIR)/l1tf: $(OBJ_DIR)/l1tf.o $(OBJ_DIR)/flush_and_reload.o $(OBJ_DIR)/statistics.o $(SRC_DIR)/ret2spec.S
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

.PHONY: hypercall
hypercall:
	$(MAKE) -C $(SRC_DIR)/hypercall

.PHONY: spectre_tester
spectre_tester:
	$(MAKE) -C $(SRC_DIR)/spectre_tester

$(BIN_DIR)/ridl: $(OBJ_DIR)/ridl.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/victim: $(OBJ_DIR)/victim.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

.PHONY: quick_ssh
quick_ssh: $(BIN_DIR)/quick_ssh
$(BIN_DIR)/quick_ssh: $(OBJ_DIR)/quick_ssh.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/rsb: $(OBJ_DIR)/find_threshold.o $(OBJ_DIR)/flush_and_reload.o $(OBJ_DIR)/rsb.o $(SRC_DIR)/ret2spec.S
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/mds: $(OBJ_DIR)/find_threshold.o $(OBJ_DIR)/flush_and_reload.o $(OBJ_DIR)/mds.o $(SRC_DIR)/ret2spec.S
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/fast_segfault_handler_test: $(SRC_DIR)/fast_segfault_handler_test.S
	$(CC) -static -z noexecstack -nostdlib $^ -o $@

$(OBJ_FILES): $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_FILES) Makefile
	@mkdir -p $(OBJ_DIR)
	$(CC) -c $(CFLAGS) $(filter %.c,$^) -o $@

.PHONY: clean
clean:
	rm -rf obj bin
	$(MAKE) -C $(SRC_DIR)/hypercall clean

print-%: ; @echo $*=$($*)
