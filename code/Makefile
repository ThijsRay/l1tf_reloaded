INC_DIR = include
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

CFLAGS += -Wall -Wextra -I$(INC_DIR) -ftrapv -z noexecstack
LDFLAGS += -lm -no-pie

SRC_FILES = $(wildcard src/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)%.c,$(OBJ_DIR)%.o,$(SRC_FILES))
INC_FILES = $(wildcard include/*.h)

$(BIN_DIR)/ridl: $(OBJ_DIR)/ridl.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/victim: $(OBJ_DIR)/victim.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/rsb: $(OBJ_DIR)/find_threshold.o $(OBJ_DIR)/flush_and_reload.o $(OBJ_DIR)/rsb.o $(SRC_DIR)/ret2spec.S
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/mds: $(OBJ_DIR)/find_threshold.o $(OBJ_DIR)/flush_and_reload.o $(OBJ_DIR)/mds.o $(SRC_DIR)/ret2spec.S
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(OBJ_FILES): $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_FILES) Makefile
	@mkdir -p $(OBJ_DIR)
	$(CC) -c $(CFLAGS) $(filter %.c,$^) -o $@

.PHONY: clean
clean:
	rm -rf obj bin
	rm -f mds

print-%: ; @echo $*=$($*)
