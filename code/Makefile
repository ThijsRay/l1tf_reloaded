CFLAGS += -Wall -Wextra -Iinclude

MDS_SOURCES = src/flush_and_reload.c src/mds.c

mds: $(MDS_SOURCES)
	$(CC) $(MDS_SOURCES) -o $@

.PHONY: clean
clean:
	rm -rf mds
