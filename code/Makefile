INC_DIR = include
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

CFLAGS += -Wall -Wextra -I$(INC_DIR)

SRC_FILES = $(wildcard src/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)%.c,$(OBJ_DIR)%.o,$(SRC_FILES))

$(BIN_DIR)/mds: $(OBJ_FILES)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@

$(OBJ_FILES): $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) -c $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -rf obj bin
	rm -f mds

print-%: ; @echo $*=$($*)
