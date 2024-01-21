INC_DIR = include
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

CFLAGS += -Wall -Wextra -I$(INC_DIR) -ftrapv
LDFLAGS += -lm

SRC_FILES = $(wildcard src/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)%.c,$(OBJ_DIR)%.o,$(SRC_FILES))
INC_FILES = $(wildcard include/*.h)

$(BIN_DIR)/mds: $(OBJ_FILES) $(INC_FILES)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(filter %.o,$^) -o $@ $(LDFLAGS)

$(OBJ_FILES): $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_FILES)
	@mkdir -p $(OBJ_DIR)
	$(CC) -c $(CFLAGS) $(filter %.c,$^) -o $@

.PHONY: clean
clean:
	rm -rf obj bin
	rm -f mds

print-%: ; @echo $*=$($*)
